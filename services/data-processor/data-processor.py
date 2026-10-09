import os
import time
import logging
from threading import Thread, Event
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from datetime import datetime
from flask import Flask, jsonify
from collections import defaultdict

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DataProcessor:
    def __init__(self):
        self.mongo_client = None
        self.stop_event = Event()
        self.metrics = {
            'processed': 0,
            'failed': 0,
            'last_processed': None,
            'errors': defaultdict(int)
        }
        self.start_time = time.time()
        
    def connect_mongodb(self):
        """Establish MongoDB connection with retries"""
        retries = 0
        max_retries = int(os.getenv('MAX_RETRIES', 3))
        retry_delay = int(os.getenv('RETRY_DELAY', 2))
        
        while retries < max_retries:
            try:
                self.mongo_client = MongoClient(
                    os.getenv('MONGODB_URI', 'mongodb://localhost:27017/'),
                    serverSelectionTimeoutMS=5000
                )
                self.mongo_client.admin.command('ping')
                logger.info("Connected to MongoDB successfully")
                return True
            except PyMongoError as e:
                retries += 1
                logger.warning(f"Connection attempt {retries} failed: {str(e)}")
                if retries < max_retries:
                    time.sleep(retry_delay)
        
        logger.error("Failed to connect to MongoDB after maximum retries")
        return False

    def process_document(self, doc):
        """Process individual document"""
        try:
            # Create processed document with metadata
            processed_doc = doc.copy()
            processed_doc['processed'] = True
            processed_doc['processing_timestamp'] = datetime.now()
            
            # Add your custom processing logic here
            # Example: processed_doc['analyzed_value'] = analyze_data(doc['raw_value'])
            
            return processed_doc
        except Exception as e:
            error_type = type(e).__name__
            logger.error(f"Error processing document {doc.get('_id')}: {str(e)}")
            self.metrics['errors'][error_type] += 1
            self.send_to_dead_letter(doc, error_type)
            return None

    def send_to_dead_letter(self, doc, error_msg):
        """Store failed documents in dead letter collection"""
        try:
            db = self.mongo_client.get_database()
            dead_letter_collection = db[os.getenv('DEAD_LETTER_COLLECTION', 'failed_data')]
            doc['error'] = str(error_msg)
            doc['failed_at'] = datetime.now()
            dead_letter_collection.insert_one(doc)
            logger.info(f"Document {doc.get('_id')} sent to dead letter queue")
        except PyMongoError as e:
            logger.error(f"Failed to send to dead letter queue: {str(e)}")

    def run_processing_cycle(self):
        """Single processing cycle"""
        try:  # Added proper try-except block
            db = self.mongo_client.get_database()
            source_collection = db[os.getenv('SOURCE_COLLECTION', 'raw_data')]
            dest_collection = db[os.getenv('DESTINATION_COLLECTION', 'processed_data')]
            
            # Fetch batch
            batch_size = int(os.getenv('BATCH_SIZE', 10))
            batch = list(source_collection.find({}).limit(batch_size))
            
            if not batch:
                return False
            
            # Process batch
            processed_docs = []
            for doc in batch:
                processed_doc = self.process_document(doc)
                if processed_doc:
                    processed_docs.append(processed_doc)
            
            # Store results
            if processed_docs:
                try:
                    dest_collection.insert_many(processed_docs)
                    # Delete originals only if storage succeeded
                    source_collection.delete_many({
                        '_id': {'$in': [doc['_id'] for doc in batch]}
                    })
                    self.metrics['processed'] += len(processed_docs)
                    self.metrics['last_processed'] = datetime.now()
                    logger.info(f"Processed {len(processed_docs)} documents")  # Fixed string quote
                    return True
                except PyMongoError as e:
                    logger.error(f"Failed to store processed documents: {str(e)}")
                    self.metrics['failed'] += len(processed_docs)
                    return False
        except Exception as e:  # Added except clause
            logger.error(f"Error in processing cycle: {str(e)}")
            return False

    def start_processing_loop(self):
        """Main processing loop"""
        processing_interval = int(os.getenv('PROCESSING_INTERVAL', 5))
        
        while not self.stop_event.is_set():
            start_time = time.time()
            
            try:
                self.run_processing_cycle()
            except Exception as e:
                logger.error(f"Processing cycle failed: {str(e)}")
                self.metrics['failed'] += 1
            
            # Throttle processing
            elapsed = time.time() - start_time
            sleep_time = max(0, processing_interval - elapsed)
            time.sleep(sleep_time)

    def start_health_server(self):
        """Start Flask health endpoint"""
        app = Flask(__name__)
        
        @app.route('/health')
        def health_check():
            return jsonify({
                'status': 'running',
                'uptime': time.time() - self.start_time,
                'metrics': self.metrics
            })
            
        app.run(host='0.0.0.0', port=5000)

    def run(self):
        """Start the processor"""
        if not self.connect_mongodb():
            return
        
        # Start health server in daemon thread
        health_thread = Thread(target=self.start_health_server, daemon=True)
        health_thread.start()
        
        # Start processing
        try:
            logger.info("Starting data processor")
            self.start_processing_loop()
        except KeyboardInterrupt:
            logger.info("Shutdown signal received")
        finally:
            self.stop_event.set()
            if self.mongo_client:
                self.mongo_client.close()
            logger.info("Processor shutdown complete")

if __name__ == '__main__':
    processor = DataProcessor()
    processor.run()