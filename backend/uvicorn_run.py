import uvicorn
import sys

# Redirect stdout and stderr to backend.log
# log_file = open("backend.log", "a")
# sys.stdout = log_file
# sys.stderr = log_file


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
