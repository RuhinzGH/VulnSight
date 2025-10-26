from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def root():
    return {"message": "Hello from VulnSight Backend 🚀"}

@app.get("/health")
def health():
    return {"status": "ok", "time": time.time()}
