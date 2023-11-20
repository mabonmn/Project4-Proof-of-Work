import sys
import hashlib
import time

def read_binary_file(file_path):
    """
    Read binary content from a file and validate it.

    Args:
    - file_path (str): Path to the file.

    Returns:
    - str: Binary content.
    """
    with open(file_path, "r") as file:
        binary_content = file.read().strip()
        if not set(binary_content).issubset({'0', '1'}):
            raise ValueError("Invalid binary content in the file.")
        return binary_content

def write_file(file_path, content):
    """
    Write content to a file.

    Args:
    - file_path (str): Path to the file.
    - content: Content to be written.
    """
    with open(file_path, "w") as file:
        file.write(str(content))

def text_to_binary(file_path, encoding="utf-8"):
    """
    Convert text content from a file to binary.

    Args:
    - file_path (str): Path to the file.
    - encoding (str): Text encoding.

    Returns:
    - str: Binary content.
    """
    with open(file_path, "r", encoding=encoding) as file:
        text_content = file.read().strip()
        binary_content = ''.join(format(ord(char), '08b') for char in text_content)
        return binary_content

def compute_target(difficulty):
    """
    Compute the target binary number.

    Args:
    - difficulty (int): Number of leading zeros in the binary target.

    Returns:
    - str: Binary target.
    """
    target_binary = '0' * difficulty + '1' * (256 - difficulty)
    return target_binary

def find_solution(input_message, target):
    """
    Find a proof-of-work solution (nonce) such that Hash(input_message + nonce) is below the target.

    Args:
    - input_message (str): The input message.
    - target (str): The binary target.

    Returns:
    - tuple: (nonce, candidate_solution)
    """
    nonce = 0
    target_int = int(target, 2)  # Convert target to integer for numerical comparison

    while True:
        candidate_solution = input_message +  bin(nonce)[2:]
        candidate_hash = hashlib.sha256(candidate_solution.encode()).hexdigest()
        candidate_binary = bin(int(candidate_hash, 16))[2:].zfill(256)

        if int(candidate_binary, 2) <= target_int:
            return nonce, nonce

        nonce += 1

def verify_solution(input_message, solution, target):
    """
    Verify if Hash(input_message + solution) is below the target.

    Args:
    - input_message (str): The input message.
    - solution (str): The candidate solution.
    - target (str): The binary target.

    Returns:
    - int: 1 if valid, 0 otherwise.
    """
    candidate_solution =  input_message +  bin(solution)[2:]
    candidate_hash = hashlib.sha256(candidate_solution.encode()).hexdigest()
    candidate_binary = bin(int(candidate_hash, 16))[2:].zfill(256)

    # Convert the target to an integer for comparison
    target_int = int(target, 2)

    return 1 if int(candidate_binary, 2) <= target_int else 0

def main():
    # Check if the difficulty level is provided as a command-line argument
    if len(sys.argv) != 2:
        print("Usage: python script.py <difficulty>")
        sys.exit(1)

    try:
        difficulty = int(sys.argv[1])
    except ValueError:
        print("Difficulty must be an integer.")
        sys.exit(1)

    # Validate the difficulty range
    if not (0 <= difficulty <= 255):
        print("Difficulty must be between 0 and 255 (inclusive).")
        sys.exit(1)

    # Compute the target
    target = compute_target(difficulty)
    
    # Write the target to the "target.txt" file
    with open("../data/target.txt", "w") as file:
        file.write(target)

    # Read the target from the file
    target_path = "../data/target.txt"
    target = read_binary_file(target_path)

    # Read the input message from the file
    input_path = "../data/input.txt"
    input_message = text_to_binary(input_path)

    # Compute the solution
    nonce, solution = find_solution(input_message, target)

    # Verify the solution
    is_valid_solution = verify_solution(input_message, solution, target)

    # Print the solution and verification result
    print("Solution Nonce:", nonce)
    print("Solution:", solution)
    print("Is Valid Solution:", is_valid_solution)

    # Write the solution to the "solution.txt" file
    solution_path = "../data/solution.txt"
    write_file(solution_path, solution)
    
if __name__ == "__main__":
    start_time = time.time()
    main()
    # Record the end time and calculate the runtime
    end_time = time.time()
    runtime = end_time - start_time
    print("Runtime:", runtime)