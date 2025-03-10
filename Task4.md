## Task 4 - LLMs never lie - (Programming, Forensics)

**Prompt 4:**

>Great work! With a credible threat proven, NSA's Cybersecurity Collaboration Center reaches out to GA and discloses the vulnerability with some indicators of compromise (IoCs) to scan for.
>
>New scan reports in hand, GA's SOC is confident they've been breached using this attack vector. They've put in a request for support from NSA, and Barry is now tasked with assisting with the incident response.
>
>While engaging the development teams directly at GA, you discover that their software engineers rely heavily on an offline LLM to assist in their workflows. A handful of developers vaguely recall once getting some confusing additions to their responses but can't remember the specifics.
>
>Barry asked for a copy of the proprietary LLM model, but approvals will take too long. Meanwhile, he was able to engage GA's IT Security to retrieve partial audit logs for the developers and access to a caching proxy for the developers' site.
>
>Barry is great at DFIR, but he knows what he doesn't know, and LLMs are outside of his wheelhouse for now. Your mutual friend Dominique was always interested in GAI and now works in Research Directorate.
>
>The developers use the LLM for help during their work duties, and their AUP allows for limited personal use. GA IT Security has bound the audit log to an estimated time period and filtered it to specific processes. Barry sent a client certificate for you to authenticate securely with the caching proxy using https://34.195.208.56/?q=query%20string.
>
>You bring Dominique up to speed on the importance of the mission. They receive a nod from their management to spend some cycles with you looking at the artifacts. You send the audit logs their way and get to work looking at this one.
>
>Find any snippet that has been purposefully altered.
>
>Downloads:
>
>Client certificate issued by the GA CA (client.crt)
>
>Client private key used to establish a secure connection (client.key)
>
>TTY audit log of a developer's shell activity (audit.log)
>
>Prompt:
>
>A maliciously altered line from a code snippet


### Solve:

So this Task gives us an audit log, as well as a certificate and key we can use to connect to a caching proxy. 

First, let's take a look at the audit log. It's really long, but remembering that we're looking for presumably LLM queries, we immediately see some interesting lines:

![image](https://github.com/user-attachments/assets/1e73fabc-4713-4570-997c-c5fb73007f13)

We see lines that begin with `gagpt -m ...`. These are likely queries to the LLM. We know that we are trying to find any suspicious lines that have been added to the LLM's responses. Well, how do we get the responses? That's where the caching server comes into play. 

We send a simple get request, using the given `.crt` and `.key` file to make the connection, to the caching server at `https://34.195.208.56/?q=query%20string`, with `query%20string` being the `gagpt -m ...` line. This will return us the LLM's response in JSON.

We can write a Python script to automate going through the audit log and find  `gagpt -m ...` lines, which we can use in our get request. 

<details>
	<Summary><b>Click to expand solve.py</b></Summary>

```Python
import re
import requests
import urllib.parse
import json

# Define the log file path and server URL
log_file_path = 'audit.log'
server_url = "https://34.195.208.56/"

# Define the certificate paths (if needed)
client_cert = 'client.crt'
client_key = 'client.key'
output_file = 'queries_and_responses.txt'

def extract_gagpt_queries(log_file_path):
    """
    Extracts 'gagpt -m' queries from the audit log.
    """
    with open(log_file_path, 'r') as log_file:
        lines = log_file.readlines()

    # Regex to match the gagpt -m queries
    gagpt_queries = []
    for line in lines:
        match = re.search(r'd=gagpt -m "(.*?)"', line)
        if match:
            query = match.group(1)
            gagpt_queries.append(query)

    return gagpt_queries

def send_query_to_server(query):
    """
    Sends a query to the server using curl-like behavior in Python with requests.
    """
    # URL encode the query
    encoded_query = urllib.parse.quote(query)
    
    # Define the URL with the query parameter
    url = f"{server_url}?q={encoded_query}"
    
    # Send the GET request
    try:
        response = requests.get(url, cert=(client_cert, client_key), verify=False)  # Disable SSL verification for now
        if response.status_code == 200:
            return response.json()  # Assuming the response is in JSON format
        else:
            return f"Error: {response.status_code} - {response.text}"
    except requests.exceptions.RequestException as e:
        return f"Request failed: {e}"

def save_query_and_response(query, response):
    """
    Saves the query and response to a file with line spacing.
    """
    with open(output_file, 'a') as file:
        file.write(f"QUERY: {query}\n")
        file.write(f"RESPONSE: {json.dumps(response, indent=2)}\n")  # Pretty-print the JSON response
        file.write("\n")  # Add a blank line for spacing

def main():
    # Extract queries from the audit log
    queries = extract_gagpt_queries(log_file_path)

    # Iterate over each query and send it to the server
    for query in queries:
        
        print(f"Sending query: {query}")
        response = send_query_to_server(query)
        save_query_and_response(query, response)
        print(f"Response saved for query: {query}")

if __name__ == '__main__':
    main()
```
</details>

This gives us a very long file of JSON, which shows the LLM's responses to the different queries, with the below image being one such example response:

![image](https://github.com/user-attachments/assets/bfe46319-7709-471e-92aa-bbeffe37b285)

Skimming through our responses, I find nothing of note, but there is something pretty interesting. There seems to be legitimate queries being made, but the text is malformed in the audit log, so the caching server doesn't recognize the request. Below is one such example:

![image](https://github.com/user-attachments/assets/c8a29a48-f091-4557-a18f-3f0e2cd5836f)

However, when you clean up these queries (fixing the spelling errors and getting rid of the extraneous characters), the LLM provides a valid response. This means that we're missing out on a whole lot of responses. 

I modified our already existing script to now allow us to specify what the query is. This allows us to clean up a malformed query we find and to individually get its response

<details>
	<Summary><b>Click to expand solve-specific.py</b></Summary>
	
```Python

import requests
import urllib.parse
import json

# Define the server URL
server_url = "https://34.195.208.56/"

# Define the certificate paths (if needed)
client_cert = 'client.crt'
client_key = 'client.key'
output_file = 'cleaned.txt'

def send_query_to_server(query):
    """
    Sends a query to the server using curl-like behavior in Python with requests.
    """
    # URL encode the query
    encoded_query = urllib.parse.quote(query)
    
    # Define the URL with the query parameter
    url = f"{server_url}?q={encoded_query}"
    
    # Send the GET request
    try:
        response = requests.get(url, cert=(client_cert, client_key), verify=False)  # Disable SSL verification for now
        if response.status_code == 200:
            return response.json()  # Assuming the response is in JSON format
        else:
            return f"Error: {response.status_code} - {response.text}"
    except requests.exceptions.RequestException as e:
        return f"Request failed: {e}"

def save_query_and_response(query, response):
    """
    Saves the query and response to a file with line spacing.
    """
    with open(output_file, 'a') as file:
        file.write(f"QUERY: {query}\n")
        file.write(f"RESPONSE: {json.dumps(response, indent=2)}\n")  # Pretty-print the JSON response
        file.write("\n")  # Add a blank line for spacing

def main():
    # Cleaned-up query
    cleaned_query = "What's the most efficient way to work with file descriptors and perform non-blocking I/O in Python using the select module"

    # Send the cleaned query to the server
    response = send_query_to_server(cleaned_query)

    # Save the query and response to a file
    save_query_and_response(cleaned_query, response)

    print(f"Response saved for query: {cleaned_query}")

if __name__ == '__main__':
    main()
```

</details>

Some of the queries obviously aren't code related. There's some revolving around a father asking for parenting advice for his daughter, someone asking about a pet python, and many other "non-serious" queries. I skimmed through to specifically get the responses for code related malformed queries, but still, there was nothing suspicious in the responses. 

Again, going through the audit log, I was trying to find anything that I may have missed. My eye then caught something, and to be honest, I got pretty lucky that I noticed it. There was one query that instead of beginning with `gagpt -m ...`, began with `gagpt m ...`, without the `-`. Since our Python script was made to find all queries that specifically began with `gagpt -m ...`, it didn't pick up on this query. 

![image](https://github.com/user-attachments/assets/da93d380-3c64-42e6-96d6-4bf78df19a60)

Cleaning it up and using our `solve-specific.py` script, we get its response, but again, it's nothing of note. 

Maybe there's other queries that begin with just `gagpt m`?

Indeed, there was one other query that was like this:

![image](https://github.com/user-attachments/assets/c68ef1f5-f81c-4e86-b3b7-229e969a5707)

I clean it up and stick it into `solve-specific.py`

![image](https://github.com/user-attachments/assets/fa93631b-3023-4ad6-bce2-2b9333147ec6)

This gets us a response, and finally along with it, the suspicious line. Or to be specific, a supsicious import that has nothing to do with the question at hand:

![image](https://github.com/user-attachments/assets/01c50550-9fdf-4944-abb9-aee89c568f75)

Our answer is `globals()['ga'] = __import__('ga513e9')`

Submitting this solves Task 4 for us!

**Results:**
>That's the snippet! I doubt the LLM is supposed to suggest an import like that.
