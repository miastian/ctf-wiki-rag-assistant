"""OpenAI 兼容的 LLM 客户端。厂商由 .env 里的 LLM_BASE_URL / LLM_API_KEY / LLM_MODEL 决定。"""
from openai import OpenAI

from secrag.config import LLM_API_KEY, LLM_BASE_URL, LLM_MODEL


class ModelClient:
    """应用调用：有限超时、禁用隐藏重试，并仅记录服务报告的用量。"""
    def __init__(self, timeout=180, max_calls=None):
        if not LLM_API_KEY or not LLM_MODEL:
            raise RuntimeError("请先配置 LLM_API_KEY 和 LLM_MODEL")
        self.client = OpenAI(base_url=LLM_BASE_URL, api_key=LLM_API_KEY,
                             timeout=timeout, max_retries=0)
        self.max_calls, self.calls, self.usage = max_calls, 0, []

    def _start(self):
        if self.max_calls is not None and self.calls >= self.max_calls:
            raise RuntimeError("已达到模型调用上限")
        self.calls += 1
        if getattr(self, 'on_call', None):
            self.on_call()

    def complete(self, messages):
        self._start()
        response = self.client.chat.completions.create(
            model=LLM_MODEL, messages=messages, temperature=0.1)
        if response.usage:
            self.usage.append(response.usage.model_dump())
        return response.choices[0].message.content or ""

    def stream(self, messages):
        self._start()
        finished = None
        with self.client.chat.completions.create(
                model=LLM_MODEL, messages=messages, temperature=0.1, stream=True,
                stream_options={"include_usage": True}) as response:
            for item in response:
                if item.usage:
                    self.usage.append(item.usage.model_dump())
                if item.choices:
                    choice = item.choices[0]
                    if choice.delta.content:
                        yield choice.delta.content
                    if choice.finish_reason:
                        finished = choice.finish_reason
        if finished != "stop":
            raise RuntimeError("模型输出中断或未完整结束")


def chat(messages: list[dict], temperature: float = 0.1) -> str:
    if not LLM_API_KEY or not LLM_MODEL:
        raise RuntimeError("请先在 .env 中配置 LLM_API_KEY 和 LLM_MODEL(参考 .env.example)")
    client = OpenAI(base_url=LLM_BASE_URL, api_key=LLM_API_KEY)
    resp = client.chat.completions.create(model=LLM_MODEL, messages=messages, temperature=temperature)
    return resp.choices[0].message.content
