from fastapi import APIRouter, UploadFile, File, HTTPException
import base64

router = APIRouter()

def image_bytes_to_string(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

@router.post("/pic/upload")
async def upload_image(file: UploadFile = File(...)) -> dict:
    if not file or not getattr(file, "content_type", "").startswith("image/"):
        raise HTTPException(status_code=400, detail="invalid_file_type")
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="empty_file")
    s = image_bytes_to_string(data)
    return {
        "success": True,
        "filename": file.filename or "",
        "content_type": file.content_type or "",
        "size": len(data),
        "string_part": s[:180],
    }