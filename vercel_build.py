"""Copy Flask's static assets to Vercel's public directory during deployment."""

import os
import shutil


BASE_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
STATIC_DIRECTORY = os.path.join(BASE_DIRECTORY, "static")
PUBLIC_STATIC_DIRECTORY = os.path.join(BASE_DIRECTORY, "public", "static")


def build_vercel_static_assets():
    """Make CSS, JavaScript, and images available through Vercel's static CDN."""
    shutil.copytree(
        STATIC_DIRECTORY,
        PUBLIC_STATIC_DIRECTORY,
        dirs_exist_ok=True,
    )
    print("Copied static assets to the Vercel public directory.")


if __name__ == "__main__":
    build_vercel_static_assets()
