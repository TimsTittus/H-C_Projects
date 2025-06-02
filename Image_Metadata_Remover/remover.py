from tkinter import Tk, filedialog
from PIL import Image
import os

def select_image():
    root = Tk()
    root.withdraw()
    return filedialog.askopenfilename(
        title="Select an image file",
        filetypes=[("Image files", "*.jpg *.jpeg *.png *.bmp *.tiff *.webp")]
    )

def remove_metadata(file_path):
    try:
        with Image.open(file_path) as image:
            data = list(image.getdata())
            clean_image = Image.new(image.mode, image.size)
            clean_image.putdata(data)

            base_name = os.path.basename(file_path)
            save_path = os.path.join(os.path.dirname(file_path), f"cleaned_{base_name}")
            clean_image.save(save_path)

            print(f" Metadata removed. Image saved as:\n{save_path}")
    except Exception as e:
        print(f"Error: {e}")

def main():
    file_path = select_image()
    if file_path:
        remove_metadata(file_path)
    else:
        print("No file selected.")

if __name__ == "__main__":
    main()