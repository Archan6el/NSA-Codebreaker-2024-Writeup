## Task 2 - Driving Me Crazy - (Forensics, DevOps)

**Prompt 2:**

>Having contacted the NSA liaison at the FBI, you learn that a facility at this address is already on a FBI watchlist for suspected criminal activity.
>With this tip, the FBI acquires a warrant and raids the location.
>
>Inside they find the empty boxes of programmable OTP tokens, but the location appears to be abandoned. We're concerned about what this APT is up to! These >hardware tokens are used to secure networks used by Defense Industrial Base companies that produce critical military hardware.
>
>The FBI sends the NSA a cache of other equipment found at the site. It is quickly assigned to an NSA forensics team. Your friend Barry enrolled in the Intrusion >Analyst Skill Development Program and is touring with that team, so you message him to get the scoop. Barry tells you that a bunch of hard drives came back with >the equipment, but most appear to be securely wiped. He managed to find a drive containing what might be some backups that they forgot to destroy, though he >doesn't immediately recognize the data. Eager to help, you ask him to send you a zip containing a copy of the supposed backup files so that you can take a look at >it.
>
>If we could recover files from the drives, it might tell us what the APT is up to. Provide a list of unique SHA256 hashes of all files you were able to find from >the backups.
>
>Downloads:
>
>disk backups (archive.tar.bz2)
>
>Prompt:
>
>Provide your list of SHA256 hashes

### Solve:

We need to provide a list of unnique SHA256 of all hashes that we can find from the compressed disk backup. First of all of course, let's run `tar -xvf` on the archive and see what we get

![image](https://github.com/user-attachments/assets/8238973b-17d9-4248-af7b-227e53e31eb5)

A whole bunch of these `logseq` files. Running the `file` command on one of them, we see that they are part of a ZFS snapshot. 

![image](https://github.com/user-attachments/assets/7dedd90d-0032-4933-9e6e-525947bc2cf4)

>Note for my fellow WSL2 users, seemingly zfs doesn't work on WSL2. In order to solve this challenge, I used a Kali virtualbox VM

When I was solving this challenge, I viewed all these `logseq` files as being essentially parts of the data on the drive, we just need to find a way to put it all together and mount it. 

After doing some research on how we can access the data in the broken up image, we have to create a a ZFS Pool and use an empty file to act as a disk image. 

First of all, the empty file. I used the `truncate` command to make a temporary file for this challenge, and placed it in my `tmp` directory:

`sudo truncate -s 10G /tmp/task2`

Now that we have the empty file, we can create our pool. I named my pool `task2pool`:

`sudo zpool create task2pool /tmp/task2`

Ok we have our pool created and ready to go. So now how do we go about putting these `logseq` files together?

After some more research, I found that we can add the files to our pool using the following syntax:

`sudo zfs receive -F task2pool/ltfs < logseq_file`

But there's one issue. We have to add them in order. 

How are we supposed to know which goes first? Well, looking back at when we ran file on one of the `logseq` files, we find two interesting things. 

![image](https://github.com/user-attachments/assets/8710e057-96e6-4732-b552-a9e968b0e4fa)

Each file has a destination and source GUID. This is what allows us to discern their order. We just have to find the first `logseq` file, which I assumed to be the one that didn't have a source GUID. 

That file ends up being `logseq291502518216656`, which is also the only `logseq` file that doesn't end in `-i`, which is a pretty telltale sign that it's likely the first one. 

![image](https://github.com/user-attachments/assets/f9091675-d7eb-492b-93d5-b87dc02a770b)

Now starting from this first file, we just add it to our pool. We then follow the destination GUID to the next `logseq` file, and add that to our pool, and continue until we've added all files. 

Of course, I didn't want to do this by hand, so I made a bash script to do it. 

```
#!/bin/bash

# Function to extract GUID from a snapshot file
get_guid() {
    local file=$1
    # Extract the GUID from the snapshot file using file command and grep
    local guid=$(file "$file" | grep -oP '(?<=destination GUID: )[^\s]+')
    echo "$guid"
}

# Function to extract the source GUID from a snapshot file
get_source_guid() {
    local file=$1
    # Extract the source GUID from the snapshot file using file command and grep
    local guid=$(file "$file" | grep -oP '(?<=source GUID: )[^\s]+')
    echo "$guid"
}

# Function to add the snapshot file to the ZFS pool
add_to_pool() {
    local file=$1
    echo "Adding $file to pool"
    sudo zfs receive -F task2pool/ltfs < "$file"
}

# Start with an initial file
current_file="logseq291502518216656"

while [ -n "$current_file" ]; do
    echo "Processing file: $current_file"
    
    # Print the file name
    echo "File name: $current_file"
    
    # Add the current snapshot file to the pool
    add_to_pool "$current_file"
    
    # Get the destination GUID of the current file
    current_dest_guid=$(get_guid "$current_file")
    
    # Find the next file based on the source GUID
    next_file=$(for file in *-i; do
        # Check if the file contains the source GUID of the current file
        if [ "$(get_source_guid "$file")" == "$current_dest_guid" ]; then
            echo "$file"
            break
        fi
    done)
    
    # Check if we found a next file
    if [ -n "$next_file" ]; then
        current_file="$next_file"
    else
        echo "No next file found. Ending script."
        break
    fi
done
```

After running this bash script, we should have all files added to our pool. Running `zfs list`, we should see our mountpoint so that we know where to go to. 

![image](https://github.com/user-attachments/assets/5d0c0712-6783-4777-bc34-92e5c94f0add)

So `/task2pool/ltfs` is where our data is. If we `cd` there, we find a `planning` directory, and within planning, a `logseq` and `pages` directory. 

![image](https://github.com/user-attachments/assets/7494b3f4-ad2b-4660-9de4-457b7a364bc4)

You would think that we just need to get the sha256 hashes of these files, call it a day, and finish this challenge, but it wasn't so easy. Submitting the hashes of these files was *not* the answer. I actually got stuck for a little bit here thinking I had the solution, and didn't know where I was doing wrong. I have the hashes of the files that are in the disk backup, which is seemingly what they were asking for. What more could you want?

It wasn't until I carefully re-read the prompt and realized what they wanted. 

**All** files that we can extract. 

