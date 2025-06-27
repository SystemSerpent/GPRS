from fastapi import FastAPI, Request, BackgroundTasks, Form, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import yt_dlp
import os
import uvicorn
import re
import asyncio
import uuid

app = FastAPI(title="Secure Youtube Video downloader")

DOWNLOAD_DIR = "downloads"
MAX_CONCURRENT_DOWNLOADS = 3
MAX_VIDEO_DURATION_SECONDS = 3600

os.makedirs(DOWNLOAD_DIR, exist_ok=True)

download_semaphore = asyncio.Semaphore(MAX_CONCURRENT_DOWNLOADS)

async def download_video_task(youtube_url: str, download_path: str, request_id: str):
	"""
	Performs the video download using yt-dlp with enhanced error handling and limits.
	This function runs in the background task.
	"""
	try:
		async with download_semaphore:
			print(f"[{request_id}] Starting download for URL: {youtube_url}")

			ydl_opts_info = {
				'quiet': True,
				'skip_download': True,
				'cachedir': False,
			}
			with yt




