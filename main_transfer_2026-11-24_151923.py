import os, re, io, hmac, hashlib, ipaddress
from urllib.parse import parse_qsl, urlparse
from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
import dns.resolver, exifread
from PIL import Image
import httpx

load_dotenv()
app = FastAPI(title="SHADOW OSINT")
app.mount("/static", StaticFiles(directory="static"), name="static")
TOKEN = os.getenv("BOT_TOKEN", "")
AUTH_REQUIRED = os.getenv("REQUIRE_TELEGRAM_AUTH", "true").lower() == "true"
MAX_BYTES = int(os.getenv("MAX_UPLOAD_MB", "10")) * 1024 * 1024

def valid_init_data(data: str) -> bool:
    if not TOKEN or not data:
        return False
    values = dict(parse_qsl(data, keep_blank_values=True))
    received = values.pop("hash", None)
    if not received:
        return False
    check = "\\n".join(f"{k}={v}" for k, v in sorted(values.items()))
    secret = hmac.new(b"WebAppData", TOKEN.encode(), hashlib.sha256).digest()
    calculated = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(calculated, received)

@app.middleware("http")
async def auth(request: Request, call_next):
    if request.url.path == "/" or request.url.path.startswith("/static"):
        return await call_next(request)
    if AUTH_REQUIRED and not valid_init_data(request.headers.get("X-Telegram-Init-Data", "")):
        return JSONResponse({"error": "Откройте приложение через Telegram."}, status_code=401)
    return await call_next(request)

@app.get("/", response_class=HTMLResponse)
async def index():
    with open("static/index.html", encoding="utf-8") as f:
        return f.read()

@app.get("/api/username")
async def username(q: str):
    q = q.strip().lstrip("@")
    if not re.fullmatch(r"[A-Za-z0-9._-]{2,32}", q):
        raise HTTPException(400, "Некорректный ник.")
    sites = {
        "Instagram": f"https://www.instagram.com/{q}/",
        "TikTok": f"https://www.tiktok.com/@{q}",
        "X": f"https://x.com/{q}",
        "GitHub": f"https://github.com/{q}",
        "Reddit": f"https://www.reddit.com/user/{q}/",
        "YouTube": f"https://www.youtube.com/@{q}",
        "Twitch": f"https://www.twitch.tv/{q}"
    }
    variants = sorted(set([q.lower(), q.upper(), q.replace("_", "."), q.replace(".", "_"),
                           q.replace("0", "o"), q.replace("1", "i"), q + "_", "_" + q]))
    return {"query": q, "profiles": [{"site": k, "url": v} for k, v in sites.items()],
            "similar_spellings": variants[:12],
            "note": "Ссылки и варианты написания для ручной проверки; наличие аккаунта не подтверждено."}

@app.get("/api/email")
async def email(q: str):
    q = q.strip()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", q):
        raise HTTPException(400, "Некорректный email.")
    domain = q.split("@", 1)[1]
    try:
        mx = [str(x.exchange).rstrip(".") for x in dns.resolver.resolve(domain, "MX")]
    except Exception:
        mx = []
    return {"email": q, "domain": domain, "mx_records": mx,
            "note": "Проверены только синтаксис и публичные MX-записи. Для проверки утечек нужен отдельный легальный API."}

@app.get("/api/phone")
async def phone(q: str):
    q = q.strip()
    if not re.fullmatch(r"\+?[0-9 ()-]{7,20}", q):
        raise HTTPException(400, "Проверьте формат номера.")
    digits = re.sub(r"\D", "", q)
    return {"input": q, "normalized": "+" + digits,
            "note": "Владелец, точное местоположение и частные сведения не определяются. Страну/тип номера можно добавить через библиотеку нумерации."}

@app.get("/api/domain")
async def domain(q: str):
    d = q.strip().lower()
    if "://" in d:
        d = urlparse(d).hostname or ""
    if not re.fullmatch(r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}", d):
        raise HTTPException(400, "Некорректный домен.")
    records = {}
    for kind in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            records[kind] = [str(x).strip('"') for x in dns.resolver.resolve(d, kind)]
        except Exception:
            records[kind] = []
    return {"domain": d, "dns": records}

@app.get("/api/ip")
async def ip_lookup(q: str):
    try:
        addr = ipaddress.ip_address(q.strip())
    except ValueError:
        raise HTTPException(400, "Некорректный IP.")
    if not addr.is_global:
        return {"ip": str(addr), "note": "IP частный или зарезервированный."}
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            data = (await client.get(f"https://ipwho.is/{addr}")).json()
    except Exception:
        data = {}
    fields = ("country", "region", "city", "connection", "timezone")
    return {"ip": str(addr), "approximate_info": {k: data.get(k) for k in fields} if data.get("success") else {},
            "note": "Геолокация IP приблизительна и не определяет точный адрес или личность."}

@app.post("/api/photo")
async def photo(file: UploadFile = File(...)):
    raw = await file.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise HTTPException(413, "Файл слишком большой.")
    try:
        img = Image.open(io.BytesIO(raw))
        tags = exifread.process_file(io.BytesIO(raw), details=False)
        wanted = ("Image Make", "Image Model", "Image DateTime", "EXIF DateTimeOriginal",
                  "EXIF DateTimeDigitized", "GPS GPSLatitude", "GPS GPSLongitude",
                  "Image Software", "EXIF ExifImageWidth", "EXIF ExifImageLength")
        metadata = {k: str(v) for k, v in tags.items() if k in wanted}
        return {"filename": file.filename, "format": img.format, "width": img.width,
                "height": img.height, "size_bytes": len(raw), "metadata": metadata,
                "note": "Если метаданные отсутствуют, их мог удалить мессенджер или редактор."}
    except Exception:
        raise HTTPException(400, "Не удалось прочитать изображение.")

@app.get("/api/health")
async def health():
    return {"ok": True, "app": "SHADOW OSINT"}
