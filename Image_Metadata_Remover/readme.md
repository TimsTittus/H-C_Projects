# Image Metadata Remover

A lightweight Python script that removes metadata from images. It allows users to select an image file through a graphical file picker and saves a clean copy without any metadata in the same folder.

## Features

* Supports common image formats: JPG, PNG, BMP, TIFF, and more.
* Easy-to-use file dialog for image selection.
* Saves a new image prefixed with `cleaned_` in the original image directory.
* Minimal dependencies (Python standard library + Pillow).

## Requirements

* Python 3.6 or higher
* [Pillow](https://python-pillow.org/) library

Install Pillow with:

```bash
pip install Pillow
```

## Usage

1. Run the script:

```bash
python remover.py
```

2. Select the image file from the dialog window.
3. The script will create a new image file prefixed with `cleaned_` in the same folder.
4. Check the console output for the save location or any errors.

## How it Works

The script reads the pixel data from the selected image and creates a new image with the same pixel data, excluding any metadata embedded in the original file.

## License

This project is licensed under the MIT License.