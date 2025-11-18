#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Script to run the ML service locally for testing.

This script sets up the environment and runs the FastAPI application
using uvicorn. It also provides options for configuring the host,
port, and other settings.
"""

import argparse
import os
import sys
import uvicorn
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the SecurityAI ML Service")
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Host to bind the server to (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8001,
        help="Port to bind the server to (default: 8001)"
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload on code changes"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of worker processes (default: 1)"
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="info",
        choices=["debug", "info", "warning", "error", "critical"],
        help="Log level (default: info)"
    )
    return parser.parse_args()


def main():
    """Run the ML service."""
    args = parse_args()
    
    # Print service information
    print("Starting SecurityAI ML Service")
    print(f"Host: {args.host}")
    print(f"Port: {args.port}")
    print(f"Reload: {args.reload}")
    print(f"Workers: {args.workers}")
    print(f"Log Level: {args.log_level}")
    
    # Set environment variables if not already set
    if not os.environ.get("MLFLOW_TRACKING_URI"):
        os.environ["MLFLOW_TRACKING_URI"] = "http://localhost:5000"
        print(f"MLFLOW_TRACKING_URI not set, using default: {os.environ['MLFLOW_TRACKING_URI']}")
    
    # Run the service
    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        workers=args.workers,
        log_level=args.log_level
    )


if __name__ == "__main__":
    main()