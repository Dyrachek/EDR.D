from huggingface_hub import hf_hub_download
import os

os.makedirs("models", exist_ok=True)

print("Скачиваю модель... это может занять несколько минут")

path = hf_hub_download(
    repo_id="Qwen/Qwen2.5-1.5B-Instruct-GGUF",
    filename="qwen2.5-1.5b-instruct-q4_k_m.gguf",
    local_dir="models",
    local_dir_use_symlinks=False,
)

print(f"Готово: {path}")