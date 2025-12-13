import sys
import os
# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchpath.config.snowflake_config import get_snowflake_session

def generate_embeddings(batch_size=5000, test_mode=False, max_rows=None, use_single_update=True):
    """
    Generate embeddings for COMBINED_TEXT column and store in EMBEDDING_VECTOR.
    Optimized for speed: tries single UPDATE first, falls back to large batches.
    
    Args:
        batch_size: Number of rows to process per batch (larger = faster, default 5000)
        test_mode: If True, only process first batch for testing
        max_rows: Maximum number of rows to process (None = all rows)
        use_single_update: If True, try single UPDATE for all rows first (fastest)
    """
    processed = 0
    session = None
    
    try:
        print("Connecting to Snowflake...")
        session = get_snowflake_session()
        print("[OK] Connected to Snowflake\n")
        
        # Check how many rows need embeddings
        count_query = """
        SELECT COUNT(*) as total_rows,
               SUM(CASE WHEN EMBEDDING_VECTOR IS NULL THEN 1 ELSE 0 END) as rows_needing_embeddings
        FROM TESTCVE.CVE.VULN_GOLD_FINAL
        """
        count_result = session.sql(count_query).collect()
        total_rows = count_result[0]["TOTAL_ROWS"]
        rows_needing = count_result[0]["ROWS_NEEDING_EMBEDDINGS"]
        
        print(f"Total rows in table: {total_rows}")
        print(f"Rows needing embeddings: {rows_needing}\n")
        
        if rows_needing == 0:
            print("[INFO] All rows already have embeddings!")
            session.close()
            return
        
        # Determine how many rows to process
        rows_to_process = min(rows_needing, max_rows) if max_rows else rows_needing
        
        if test_mode:
            rows_to_process = min(batch_size, rows_to_process)
            print(f"[TEST MODE] Processing first {rows_to_process} rows only\n")
        else:
            print(f"Will process {rows_to_process} rows\n")
        
        # OPTIMIZATION: Try single UPDATE first (fastest approach)
        if use_single_update and not test_mode:
            print("="*60)
            print("ATTEMPTING FASTEST METHOD: Single UPDATE for all rows...")
            print("="*60)
            try:
                bulk_update_all = """
                UPDATE TESTCVE.CVE.VULN_GOLD_FINAL
                SET EMBEDDING_VECTOR = SNOWFLAKE.CORTEX.EMBED_TEXT_1024(
                    'snowflake-arctic-embed-l-v2.0',
                    COMBINED_TEXT
                )::VECTOR(FLOAT, 1024)
                WHERE EMBEDDING_VECTOR IS NULL
                  AND COMBINED_TEXT IS NOT NULL
                  AND COMBINED_TEXT != ''
                """
                
                print("Executing single UPDATE statement (this may take a while)...")
                result = session.sql(bulk_update_all).collect()
                
                # Verify how many were updated
                verify_query = """
                SELECT COUNT(*) as updated_count
                FROM TESTCVE.CVE.VULN_GOLD_FINAL
                WHERE EMBEDDING_VECTOR IS NOT NULL
                """
                verify_result = session.sql(verify_query).collect()
                updated_count = verify_result[0]["UPDATED_COUNT"]
                
                print(f"\n[OK] Single UPDATE completed!")
                print(f"[OK] Total rows with embeddings: {updated_count}")
                print("[OK] Snowflake session closed")
                session.close()
                return
                
            except Exception as e:
                error_msg = str(e)
                if "statement timeout" in error_msg.lower() or "too many" in error_msg.lower():
                    print(f"[INFO] Single UPDATE failed (likely too many rows): {error_msg[:100]}...")
                    print("[INFO] Falling back to optimized batch processing...\n")
                else:
                    print(f"[WARNING] Single UPDATE failed: {error_msg}")
                    print("[INFO] Falling back to batch processing...\n")
        
        # FALLBACK: Process in large batches using MERGE
        print("="*60)
        print(f"Using optimized batch processing (batch size: {batch_size})...")
        print("="*60)
        
        processed = 0
        
        while processed < rows_to_process:
            remaining = rows_to_process - processed
            current_batch = min(batch_size, remaining)
            
            print(f"\nProcessing batch: {processed + 1} to {processed + current_batch} rows...")
            
            # Use MERGE to update multiple rows at once
            bulk_update_query = f"""
            MERGE INTO TESTCVE.CVE.VULN_GOLD_FINAL AS target
            USING (
                SELECT 
                    CVE_ID,
                    SNOWFLAKE.CORTEX.EMBED_TEXT_1024(
                        'snowflake-arctic-embed-l-v2.0',
                        COMBINED_TEXT
                    )::VECTOR(FLOAT, 1024) AS new_embedding
                FROM TESTCVE.CVE.VULN_GOLD_FINAL
                WHERE EMBEDDING_VECTOR IS NULL
                  AND COMBINED_TEXT IS NOT NULL
                  AND COMBINED_TEXT != ''
                LIMIT {current_batch}
            ) AS source
            ON target.CVE_ID = source.CVE_ID
            WHEN MATCHED THEN
                UPDATE SET EMBEDDING_VECTOR = source.new_embedding
            """
            
            try:
                result = session.sql(bulk_update_query).collect()
                # MERGE doesn't return row count directly, so we check
                check_query = """
                SELECT COUNT(*) as updated_count
                FROM TESTCVE.CVE.VULN_GOLD_FINAL
                WHERE EMBEDDING_VECTOR IS NOT NULL
                """
                check_result = session.sql(check_query).collect()
                current_updated = check_result[0]["UPDATED_COUNT"]
                
                # Calculate how many were just updated
                rows_updated = current_updated - processed if current_updated > processed else current_batch
                processed = current_updated
                
                print(f"  ✓ Updated {rows_updated} rows (Total: {processed}/{rows_to_process})")
                
                # Check if we're done
                if rows_updated == 0:
                    print("\n[INFO] No more rows to process")
                    break
                    
            except Exception as e:
                print(f"  [ERROR] Batch failed: {e}")
                print("  Trying smaller batch size...")
                # Try with smaller batch if this fails
                if batch_size > 500:
                    batch_size = max(500, batch_size // 2)
                    print(f"  Reduced batch size to {batch_size}")
                    continue
                else:
                    print("  [ERROR] Even small batch failed. Stopping.")
                    break
            
            if test_mode:
                break
        
        print(f"\n[OK] Completed! Processed {processed} rows")
        print("[OK] Snowflake session closed")
        if session:
            session.close()
        
    except KeyboardInterrupt:
        print("\n\n[INFO] Process interrupted by user")
        print(f"[INFO] Processed {processed} rows before stopping")
        if session:
            session.close()
    except Exception as e:
        print(f"[ERROR] Failed: {e}")
        import traceback
        traceback.print_exc()
        if session:
            session.close()

if __name__ == "__main__":
    # Process all rows with optimized approach
    print("="*60)
    print("Vector Embedding Generation - Optimized Fast Processing")
    print("="*60)
    print("\nStrategy:")
    print("1. First attempts single UPDATE for all rows (fastest)")
    print("2. Falls back to large batch processing (5000 rows/batch) if needed")
    print("="*60)
    print()
    
    # Process ALL rows with optimized settings
    generate_embeddings(batch_size=5000, test_mode=False, use_single_update=True)