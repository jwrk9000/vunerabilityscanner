# search_and_save_keywords.py

def count_occurrences(file_path, keywords):
    try:
        with open(file_path, 'r') as file:
            content = file.read().lower()
            occurrences = {keyword: content.count(keyword) for keyword in keywords}
            return occurrences
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return {}

def save_occurrences_to_file(output_file_path, occurrences):
    with open(output_file_path, 'a') as output_file:
        for keyword, count in occurrences.items():
            output_file.write(f"The word '{keyword}' is mentioned {count} times.\n")

if __name__ == "__main__":
    input_file_path = input("Enter the path to the input database text file: ")
    output_file_path = input("Enter the path to the output database text file: ")

    # Specify the keywords to search for (case-insensitive)
    keywords_to_search = ["cookie", "admin", "login"]

    # Count occurrences of the keywords in the input file
    occurrences = count_occurrences(input_file_path, keywords_to_search)

    # Save occurrences to the output file
    save_occurrences_to_file(output_file_path, occurrences)

    print(f"Results saved to {output_file_path}")
