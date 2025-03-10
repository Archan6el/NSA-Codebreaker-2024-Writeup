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

We send a simple get request to the caching server, using the given `.crt` and `.key` file to make the connection, to `https://34.195.208.56/?q=query%20string`, with `query%20string` being the `gagpt -m ...` line. 

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
