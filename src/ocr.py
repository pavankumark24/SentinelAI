import pytesseract
from PIL import Image

pytesseract.pytesseract.tesseract_cmd = (
    r"C:\Program Files\Tesseract-OCR\tesseract.exe"
)

def extract_text(image):

    img = Image.open(image)

    text = pytesseract.image_to_string(img)

    return text