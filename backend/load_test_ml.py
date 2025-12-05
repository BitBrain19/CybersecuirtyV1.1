import asyncio
import time
import httpx
import statistics
from typing import List

# Configuration
BASE_URL = "http://localhost:8000/api/v1"  # Backend URL
NUM_REQUESTS = 100
CONCURRENCY = 10

async def test_endpoint(client: httpx.AsyncClient, endpoint: str, payload: dict = None):
    start_time = time.time()
    try:
        if payload:
            response = await client.post(f"{BASE_URL}{endpoint}", json=payload)
        else:
            response = await client.get(f"{BASE_URL}{endpoint}")
        
        response.raise_for_status()
        duration = (time.time() - start_time) * 1000
        return {"status": "success", "duration": duration, "code": response.status_code}
    except Exception as e:
        duration = (time.time() - start_time) * 1000
        return {"status": "error", "duration": duration, "error": str(e)}

async def run_load_test():
    print(f"Starting load test: {NUM_REQUESTS} requests with concurrency {CONCURRENCY}")
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        # 1. Test Threat Detection (POST)
        print("\nTesting Threat Detection Endpoint...")
        tasks = []
        payload = {
            "features": {
                "source_ip": "192.168.1.100",
                "destination_port": 80,
                "protocol": "TCP",
                "packet_count": 500,
                "byte_count": 2048
            },
            "model_name": "threat_detection"
        }
        
        start_total = time.time()
        for _ in range(NUM_REQUESTS):
            tasks.append(test_endpoint(client, "/ml/predict", payload))
            if len(tasks) >= CONCURRENCY:
                await asyncio.gather(*tasks)
                tasks = []
        
        if tasks:
            await asyncio.gather(*tasks)
            
        total_time = time.time() - start_total
        print(f"Completed in {total_time:.2f}s")

if __name__ == "__main__":
    asyncio.run(run_load_test())
