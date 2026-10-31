"""Thêm src/ vào sys.path để chạy `python -m pytest` từ thư mục gốc dự án."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
