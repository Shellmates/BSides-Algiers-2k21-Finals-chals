FROM python:3.9.9-slim

RUN pip install fastapi fastapi-utils numpy "uvicorn[standard]"
WORKDIR /app
COPY main.py /app
COPY tfhe /app/tfhe

# Flag for the challenge
ENV FLAG=shellmates{rlw3_1s_fun__y0u_c4n_p14y_w1th_1t}

ENTRYPOINT ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]