import os
import argparse
import pefile
import time
import pandas as pd
from pefile import PEFormatError
from concurrent.futures import ThreadPoolExecutor

def timing_decorator(func):
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        execution_time = end_time - start_time
        print(f"Execution time: {execution_time:.2f} seconds")
        return result
    return wrapper

def calculate_imphash(file_path):
    try:
        pe = pefile.PE(file_path)
        imphash = pe.get_imphash()
        return imphash
    except PEFormatError as e:
        return None

def scan_file(file_path):
    imphash = calculate_imphash(file_path)
    if imphash:
        return (file_path, imphash)
    return None

def scan_directory(directory, recursive=False):
    imphash_dict = {}
    with ThreadPoolExecutor() as executor:
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if not recursive and os.path.isdir(file_path):
                    continue
                imphash_result = executor.submit(scan_file, file_path)
                if imphash_result.result():
                    imphash_dict[file_path] = imphash_result.result()
    return imphash_dict

@timing_decorator
def main():
    parser = argparse.ArgumentParser(description="Calculate imphash of files in a directory and save the results to XLSX.")
    parser.add_argument("-r", "--recursive", action="store_true", help="Scan directories recursively.")
    parser.add_argument("-p", "--path", help="Specify the directory to scan.")
    parser.add_argument("-f", "--file", help="Specify a single file to scan.")
    parser.add_argument("-o", "--output", help="Specify the output XLSX file.")
    args = parser.parse_args()

    if args.file:
        file_path = os.path.normpath(args.file)
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            return
        imphash = calculate_imphash(file_path)
        if imphash:
            print(f"Imphash for {file_path}: {imphash}")
    elif args.path:
        directory = os.path.normpath(args.path)
        if args.recursive:
            imphash_dict = scan_directory(directory, recursive=True)
        else:
            imphash_dict = scan_directory(directory)
        
        if not imphash_dict:
            print("No imphash data to save.")
            return

        print()
        # Создаем DataFrame с двумя колонками
        df = pd.DataFrame.from_dict(imphash_dict, orient='index', columns=['File', 'Imphash'])
        df.index.name = 'File Path'  # Устанавливаем имя индекса

        if args.output:
            df.reset_index(inplace=True)  # Сбрасываем индекс, чтобы он стал колонкой
            df.to_excel(args.output, index=False)
            print(f"Results saved to {args.output}")
        else:
            print(df)
    else:
        print("Please specify either a directory with -p or a file with -f.")

if __name__ == "__main__":
    main()
