from src.ocr import extract_text

text = extract_text("test.png")

print("START")
print(repr(text))
print("END")