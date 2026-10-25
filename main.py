# ... (all the FastAPI code from the first response) ...

if __name__ == "__main__":
    import uvicorn
    import os
    # Render assigns a dynamic port via the PORT environment variable
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)