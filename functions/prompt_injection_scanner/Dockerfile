FROM public.ecr.aws/lambda/python:3.12

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download ONNX model at build time so it's baked into the image
RUN python -c "\
from huggingface_hub import snapshot_download; \
snapshot_download( \
    'protectai/deberta-v3-base-prompt-injection-v2', \
    local_dir='/opt/model', \
    allow_patterns=['onnx/*', 'tokenizer*', 'special_tokens_map.json', 'spm.model'], \
)"

ENV MODEL_PATH=/opt/model

COPY handler.py ${LAMBDA_TASK_ROOT}/

CMD ["handler.handler"]
