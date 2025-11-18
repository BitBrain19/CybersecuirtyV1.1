"""Batch Processing System for Efficient Bulk Predictions

This module provides batch processing capabilities for handling
large volumes of prediction requests efficiently.
"""

import asyncio
import logging
import time
import json
import pickle
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Callable, Iterator
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import threading
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import multiprocessing as mp
from queue import Queue, Empty
import pandas as pd
import numpy as np

from ..models.threat_detection import get_threat_detector
from ..models.vulnerability_assessment import get_vulnerability_assessor
from ..core.exceptions import BatchProcessingError
from ..core.config import get_config
from ..core.error_handler import with_error_recovery, RecoveryStrategy, RecoveryAction

logger = logging.getLogger(__name__)

class BatchStatus(Enum):
    """Batch processing status."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class ProcessingMode(Enum):
    """Processing mode options."""
    SEQUENTIAL = "sequential"
    THREADED = "threaded"
    MULTIPROCESS = "multiprocess"
    ASYNC = "async"

@dataclass
class BatchConfig:
    """Batch processing configuration."""
    batch_size: int = 100
    max_workers: int = 4
    processing_mode: ProcessingMode = ProcessingMode.THREADED
    chunk_size: int = 1000
    memory_limit_mb: int = 1024
    timeout_seconds: int = 3600
    retry_attempts: int = 3
    save_intermediate: bool = True
    output_format: str = "json"  # json, csv, pickle
    compression: bool = True

@dataclass
class BatchItem:
    """Individual batch item."""
    item_id: str
    data: Dict[str, Any]
    model_type: str
    priority: int = 1
    metadata: Dict[str, Any] = field(default_factory=dict)
    processed: bool = False
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    processing_time: Optional[float] = None

@dataclass
class BatchJob:
    """Batch processing job."""
    job_id: str
    name: str
    items: List[BatchItem]
    config: BatchConfig
    status: BatchStatus = BatchStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    progress: float = 0.0
    total_items: int = 0
    processed_items: int = 0
    failed_items: int = 0
    results: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    output_path: Optional[str] = None
    metrics: Dict[str, Any] = field(default_factory=dict)

class BatchProcessor:
    """High-performance batch processor for ML predictions."""
    
    def __init__(self, config: Optional[BatchConfig] = None):
        self.config = config or BatchConfig()
        self.app_config = get_config()
        
        # Model instances
        self.threat_detector = get_threat_detector()
        self.vulnerability_assessor = get_vulnerability_assessor()
        
        # Job management
        self.active_jobs: Dict[str, BatchJob] = {}
        self.job_history: List[BatchJob] = []
        self.job_lock = threading.Lock()
        
        # Processing resources
        self.thread_pool = ThreadPoolExecutor(max_workers=self.config.max_workers)
        self.process_pool = ProcessPoolExecutor(max_workers=min(self.config.max_workers, mp.cpu_count()))
        
        # Statistics
        self.stats = {
            'total_jobs': 0,
            'completed_jobs': 0,
            'failed_jobs': 0,
            'total_items_processed': 0,
            'average_processing_time': 0.0,
            'throughput_items_per_second': 0.0
        }
        
        # Output directory
        self.output_dir = Path(self.app_config.get('batch_output_dir', './batch_outputs'))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Batch processor initialized with {self.config.max_workers} workers")
    
    @with_error_recovery("BatchProcessor", RecoveryStrategy(RecoveryAction.RETRY, max_attempts=2))
    def create_job(self, name: str, items: List[Dict[str, Any]], 
                   model_type: str, config: Optional[BatchConfig] = None) -> str:
        """Create a new batch processing job."""
        job_id = f"batch_{int(time.time())}_{hash(name) % 10000}"
        job_config = config or self.config
        
        # Convert items to BatchItem objects
        batch_items = [
            BatchItem(
                item_id=f"{job_id}_{i}",
                data=item,
                model_type=model_type,
                priority=item.get('priority', 1)
            )
            for i, item in enumerate(items)
        ]
        
        # Create job
        job = BatchJob(
            job_id=job_id,
            name=name,
            items=batch_items,
            config=job_config,
            total_items=len(batch_items)
        )
        
        with self.job_lock:
            self.active_jobs[job_id] = job
            self.stats['total_jobs'] += 1
        
        logger.info(f"Created batch job {job_id} with {len(batch_items)} items")
        return job_id
    
    def create_job_from_file(self, name: str, file_path: str, model_type: str, 
                           data_column: str = 'data', config: Optional[BatchConfig] = None) -> str:
        """Create batch job from file (CSV, JSON, or pickle)."""
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise BatchProcessingError(f"File not found: {file_path}")
        
        # Load data based on file extension
        if file_path.suffix.lower() == '.csv':
            df = pd.read_csv(file_path)
            items = df.to_dict('records')
        elif file_path.suffix.lower() == '.json':
            with open(file_path, 'r') as f:
                data = json.load(f)
                items = data if isinstance(data, list) else [data]
        elif file_path.suffix.lower() in ['.pkl', '.pickle']:
            with open(file_path, 'rb') as f:
                items = pickle.load(f)
        else:
            raise BatchProcessingError(f"Unsupported file format: {file_path.suffix}")
        
        logger.info(f"Loaded {len(items)} items from {file_path}")
        return self.create_job(name, items, model_type, config)
    
    async def process_job_async(self, job_id: str) -> BatchJob:
        """Process job asynchronously."""
        job = self._get_job(job_id)
        
        if job.status != BatchStatus.PENDING:
            raise BatchProcessingError(f"Job {job_id} is not in pending status")
        
        job.status = BatchStatus.PROCESSING
        job.started_at = datetime.now()
        
        try:
            if job.config.processing_mode == ProcessingMode.ASYNC:
                await self._process_async_mode(job)
            else:
                # Run sync processing in thread pool
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, self._process_sync_modes, job)
            
            job.status = BatchStatus.COMPLETED
            job.completed_at = datetime.now()
            
            # Save results
            await self._save_results(job)
            
            # Update statistics
            self._update_stats(job)
            
            with self.job_lock:
                if job_id in self.active_jobs:
                    del self.active_jobs[job_id]
                self.job_history.append(job)
                self.stats['completed_jobs'] += 1
            
            logger.info(f"Completed batch job {job_id} in {self._get_processing_time(job):.2f}s")
            
        except Exception as e:
            job.status = BatchStatus.FAILED
            job.errors.append(str(e))
            
            with self.job_lock:
                self.stats['failed_jobs'] += 1
            
            logger.error(f"Batch job {job_id} failed: {str(e)}")
            raise BatchProcessingError(f"Job processing failed: {str(e)}")
        
        return job
    
    def process_job_sync(self, job_id: str) -> BatchJob:
        """Process job synchronously."""
        job = self._get_job(job_id)
        
        if job.status != BatchStatus.PENDING:
            raise BatchProcessingError(f"Job {job_id} is not in pending status")
        
        job.status = BatchStatus.PROCESSING
        job.started_at = datetime.now()
        
        try:
            self._process_sync_modes(job)
            
            job.status = BatchStatus.COMPLETED
            job.completed_at = datetime.now()
            
            # Save results synchronously
            asyncio.run(self._save_results(job))
            
            # Update statistics
            self._update_stats(job)
            
            with self.job_lock:
                if job_id in self.active_jobs:
                    del self.active_jobs[job_id]
                self.job_history.append(job)
                self.stats['completed_jobs'] += 1
            
            logger.info(f"Completed batch job {job_id} in {self._get_processing_time(job):.2f}s")
            
        except Exception as e:
            job.status = BatchStatus.FAILED
            job.errors.append(str(e))
            
            with self.job_lock:
                self.stats['failed_jobs'] += 1
            
            logger.error(f"Batch job {job_id} failed: {str(e)}")
            raise BatchProcessingError(f"Job processing failed: {str(e)}")
        
        return job
    
    def _process_sync_modes(self, job: BatchJob) -> None:
        """Process job using synchronous modes."""
        if job.config.processing_mode == ProcessingMode.SEQUENTIAL:
            self._process_sequential(job)
        elif job.config.processing_mode == ProcessingMode.THREADED:
            self._process_threaded(job)
        elif job.config.processing_mode == ProcessingMode.MULTIPROCESS:
            self._process_multiprocess(job)
        else:
            raise BatchProcessingError(f"Unsupported processing mode: {job.config.processing_mode}")
    
    def _process_sequential(self, job: BatchJob) -> None:
        """Process items sequentially."""
        for item in job.items:
            try:
                start_time = time.time()
                result = self._process_single_item(item)
                item.result = result
                item.processed = True
                item.processing_time = time.time() - start_time
                
                job.processed_items += 1
                job.progress = (job.processed_items / job.total_items) * 100
                
            except Exception as e:
                item.error = str(e)
                job.failed_items += 1
                logger.error(f"Failed to process item {item.item_id}: {str(e)}")
    
    def _process_threaded(self, job: BatchJob) -> None:
        """Process items using thread pool."""
        # Submit all items to thread pool
        future_to_item = {
            self.thread_pool.submit(self._process_single_item, item): item
            for item in job.items
        }
        
        # Collect results
        for future in as_completed(future_to_item, timeout=job.config.timeout_seconds):
            item = future_to_item[future]
            
            try:
                start_time = time.time()
                result = future.result()
                item.result = result
                item.processed = True
                item.processing_time = time.time() - start_time
                
                job.processed_items += 1
                job.progress = (job.processed_items / job.total_items) * 100
                
            except Exception as e:
                item.error = str(e)
                job.failed_items += 1
                logger.error(f"Failed to process item {item.item_id}: {str(e)}")
    
    def _process_multiprocess(self, job: BatchJob) -> None:
        """Process items using process pool."""
        # Prepare data for multiprocessing
        items_data = [(item.data, item.model_type) for item in job.items]
        
        # Submit to process pool
        future_to_index = {
            self.process_pool.submit(process_item_worker, data, model_type): i
            for i, (data, model_type) in enumerate(items_data)
        }
        
        # Collect results
        for future in as_completed(future_to_index, timeout=job.config.timeout_seconds):
            index = future_to_index[future]
            item = job.items[index]
            
            try:
                start_time = time.time()
                result = future.result()
                item.result = result
                item.processed = True
                item.processing_time = time.time() - start_time
                
                job.processed_items += 1
                job.progress = (job.processed_items / job.total_items) * 100
                
            except Exception as e:
                item.error = str(e)
                job.failed_items += 1
                logger.error(f"Failed to process item {item.item_id}: {str(e)}")
    
    async def _process_async_mode(self, job: BatchJob) -> None:
        """Process items asynchronously."""
        semaphore = asyncio.Semaphore(job.config.max_workers)
        
        async def process_item_async(item: BatchItem) -> None:
            async with semaphore:
                try:
                    start_time = time.time()
                    # Run in thread pool to avoid blocking
                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(None, self._process_single_item, item)
                    
                    item.result = result
                    item.processed = True
                    item.processing_time = time.time() - start_time
                    
                    job.processed_items += 1
                    job.progress = (job.processed_items / job.total_items) * 100
                    
                except Exception as e:
                    item.error = str(e)
                    job.failed_items += 1
                    logger.error(f"Failed to process item {item.item_id}: {str(e)}")
        
        # Process all items concurrently
        tasks = [process_item_async(item) for item in job.items]
        await asyncio.gather(*tasks, return_exceptions=True)
    
    def _process_single_item(self, item: BatchItem) -> Dict[str, Any]:
        """Process a single batch item."""
        if item.model_type == 'threat_detection':
            return self.threat_detector.predict(item.data)
        elif item.model_type == 'vulnerability_assessment':
            return self.vulnerability_assessor.predict(item.data)
        else:
            raise BatchProcessingError(f"Unknown model type: {item.model_type}")
    
    async def _save_results(self, job: BatchJob) -> None:
        """Save job results to file."""
        if not job.config.save_intermediate:
            return
        
        # Prepare results data
        results_data = []
        for item in job.items:
            result_entry = {
                'item_id': item.item_id,
                'processed': item.processed,
                'processing_time': item.processing_time,
                'result': item.result,
                'error': item.error
            }
            results_data.append(result_entry)
        
        # Determine output path
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{job.name}_{job.job_id}_{timestamp}"
        
        if job.config.output_format == 'json':
            output_path = self.output_dir / f"{filename}.json"
            with open(output_path, 'w') as f:
                json.dump({
                    'job_info': {
                        'job_id': job.job_id,
                        'name': job.name,
                        'total_items': job.total_items,
                        'processed_items': job.processed_items,
                        'failed_items': job.failed_items,
                        'processing_time': self._get_processing_time(job)
                    },
                    'results': results_data
                }, f, indent=2)
        
        elif job.config.output_format == 'csv':
            output_path = self.output_dir / f"{filename}.csv"
            df = pd.DataFrame(results_data)
            df.to_csv(output_path, index=False)
        
        elif job.config.output_format == 'pickle':
            output_path = self.output_dir / f"{filename}.pkl"
            with open(output_path, 'wb') as f:
                pickle.dump({
                    'job': job,
                    'results': results_data
                }, f)
        
        job.output_path = str(output_path)
        logger.info(f"Saved results to {output_path}")
    
    def _get_job(self, job_id: str) -> BatchJob:
        """Get job by ID."""
        with self.job_lock:
            if job_id not in self.active_jobs:
                raise BatchProcessingError(f"Job {job_id} not found")
            return self.active_jobs[job_id]
    
    def _get_processing_time(self, job: BatchJob) -> float:
        """Get job processing time in seconds."""
        if job.started_at and job.completed_at:
            return (job.completed_at - job.started_at).total_seconds()
        return 0.0
    
    def _update_stats(self, job: BatchJob) -> None:
        """Update processing statistics."""
        processing_time = self._get_processing_time(job)
        
        with self.job_lock:
            self.stats['total_items_processed'] += job.processed_items
            
            # Update average processing time
            total_time = self.stats['average_processing_time'] * self.stats['completed_jobs']
            self.stats['average_processing_time'] = (total_time + processing_time) / (self.stats['completed_jobs'] + 1)
            
            # Update throughput
            if processing_time > 0:
                throughput = job.processed_items / processing_time
                total_throughput = self.stats['throughput_items_per_second'] * self.stats['completed_jobs']
                self.stats['throughput_items_per_second'] = (total_throughput + throughput) / (self.stats['completed_jobs'] + 1)
    
    def get_job_status(self, job_id: str) -> Dict[str, Any]:
        """Get current job status."""
        job = self._get_job(job_id)
        
        return {
            'job_id': job.job_id,
            'name': job.name,
            'status': job.status.value,
            'progress': job.progress,
            'total_items': job.total_items,
            'processed_items': job.processed_items,
            'failed_items': job.failed_items,
            'created_at': job.created_at.isoformat(),
            'started_at': job.started_at.isoformat() if job.started_at else None,
            'completed_at': job.completed_at.isoformat() if job.completed_at else None,
            'processing_time': self._get_processing_time(job),
            'output_path': job.output_path
        }
    
    def cancel_job(self, job_id: str) -> bool:
        """Cancel a running job."""
        job = self._get_job(job_id)
        
        if job.status == BatchStatus.PROCESSING:
            job.status = BatchStatus.CANCELLED
            logger.info(f"Cancelled job {job_id}")
            return True
        
        return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive processing statistics."""
        with self.job_lock:
            active_jobs_count = len(self.active_jobs)
            
            return {
                'total_jobs': self.stats['total_jobs'],
                'completed_jobs': self.stats['completed_jobs'],
                'failed_jobs': self.stats['failed_jobs'],
                'active_jobs': active_jobs_count,
                'total_items_processed': self.stats['total_items_processed'],
                'average_processing_time': self.stats['average_processing_time'],
                'throughput_items_per_second': self.stats['throughput_items_per_second'],
                'success_rate': (
                    self.stats['completed_jobs'] / max(self.stats['total_jobs'], 1)
                ) * 100
            }
    
    def cleanup_old_jobs(self, days: int = 7) -> int:
        """Clean up old job history."""
        cutoff_date = datetime.now() - timedelta(days=days)
        
        with self.job_lock:
            initial_count = len(self.job_history)
            self.job_history = [
                job for job in self.job_history
                if job.created_at >= cutoff_date
            ]
            cleaned_count = initial_count - len(self.job_history)
        
        logger.info(f"Cleaned up {cleaned_count} old jobs")
        return cleaned_count
    
    def shutdown(self) -> None:
        """Shutdown the batch processor."""
        logger.info("Shutting down batch processor")
        
        # Cancel all active jobs
        with self.job_lock:
            for job_id in list(self.active_jobs.keys()):
                self.cancel_job(job_id)
        
        # Shutdown thread pools
        self.thread_pool.shutdown(wait=True)
        self.process_pool.shutdown(wait=True)
        
        logger.info("Batch processor shutdown complete")

def process_item_worker(data: Dict[str, Any], model_type: str) -> Dict[str, Any]:
    """Worker function for multiprocessing."""
    # This function runs in a separate process
    # Need to recreate model instances
    if model_type == 'threat_detection':
        detector = get_threat_detector()
        return detector.predict(data)
    elif model_type == 'vulnerability_assessment':
        assessor = get_vulnerability_assessor()
        return assessor.predict(data)
    else:
        raise BatchProcessingError(f"Unknown model type: {model_type}")

# Global batch processor instance
_batch_processor: Optional[BatchProcessor] = None

def get_batch_processor(config: Optional[BatchConfig] = None) -> BatchProcessor:
    """Get global batch processor instance."""
    global _batch_processor
    if _batch_processor is None:
        _batch_processor = BatchProcessor(config)
    return _batch_processor