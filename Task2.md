## Task 2 - Driving Me Crazy - (Forensics, DevOps)

**Prompt 2:**

>Having contacted the NSA liaison at the FBI, you learn that a facility at this address is already on a FBI watchlist for suspected criminal activity.
>With this tip, the FBI acquires a warrant and raids the location.
>
>Inside they find the empty boxes of programmable OTP tokens, but the location appears to be abandoned. We're concerned about what this APT is up to! These hardware tokens are used to secure networks used by Defense Industrial Base companies that produce critical military hardware.
>
>The FBI sends the NSA a cache of other equipment found at the site. It is quickly assigned to an NSA forensics team. Your friend Barry enrolled in the Intrusion Analyst Skill Development Program and is touring with that team, so you message him to get the scoop. Barry tells you that a bunch of hard drives came back with the equipment, but most appear to be securely wiped. He managed to find a drive containing what might be some backups that they forgot to destroy, though he doesn't immediately recognize the data. Eager to help, you ask him to send you a zip containing a copy of the supposed backup files so that you can take a look at it.
>
>If we could recover files from the drives, it might tell us what the APT is up to. Provide a list of unique SHA256 hashes of all files you were able to find from the backups.
>
>Downloads:
>
>disk backups (archive.tar.bz2)
>
>Prompt:
>
>Provide your list of SHA256 hashes

### Solve:

We need to provide a list of all unique SHA256 hashes that we can find from the compressed disk backup we are given. 

First of all, let's run `tar -xvf` on the archive and see what we get

![image](https://github.com/user-attachments/assets/8238973b-17d9-4248-af7b-227e53e31eb5)

A whole bunch of these `logseq` files. 

After running the `file` command on one of them, we see that they are part of a ZFS snapshot. 

![image](https://github.com/user-attachments/assets/7dedd90d-0032-4933-9e6e-525947bc2cf4)

>Note for my fellow WSL2 users, seemingly zfs doesn't work on WSL2. In order to solve this challenge, I used a Kali virtualbox VM

After doing some googling on ZFS, I learn that all of these `logseq` files are essentially parts of the data on the drive, we just need to find a way to put them all together and mount or access the final result. 

After doing some research on how we can access the data in the broken up drive, I found that you have to create a ZFS Pool and use an empty file to act as a virtual disk image. 

First of all, the empty file. I used the `truncate` command to make a temporary file for this challenge, and placed it in my `tmp` directory:

`sudo truncate -s 10G /tmp/task2`

Now that we have the empty file, we can create our pool using it. I named my pool `task2pool`:

`sudo zpool create task2pool /tmp/task2`

OK we have our pool created and ready to go. So now how do we go about putting these `logseq` files together?

After some more research, I found that we can add the files to our pool using the following command:

`sudo zfs receive -F task2pool/ltfs < logseq_file`

But there's one issue. We have to add / recieve them in order, `logseq` files are incremental. 

How are we supposed to know which goes first? Well, looking back at when we ran `file` on one of the `logseq` files, we find two interesting things. 

![image](https://github.com/user-attachments/assets/8710e057-96e6-4732-b552-a9e968b0e4fa)

Each file has a destination and source GUID. This is what allows us to discern their order. We just have to find the first `logseq` file, which I assumed to be the one that didn't have a source GUID. 

That file ends up being `logseq291502518216656`, which is also the only `logseq` file that doesn't end in `-i`, which is a pretty telltale sign that it's likely the first one. 

![image](https://github.com/user-attachments/assets/f9091675-d7eb-492b-93d5-b87dc02a770b)

Now starting from this first file, we add it to our pool. We then follow the destination GUID to the next `logseq` file, and add that to our pool, and continue until we've added all files. 

Of course, I didn't want to do this by hand, so I made a bash script to do it. 

```bash
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

After running this bash script, we should have all files added to our pool. Running `zfs list`, we should see our mountpoint so that we know where to go to look at the final product. 

![image](https://github.com/user-attachments/assets/5d0c0712-6783-4777-bc34-92e5c94f0add)

So `/task2pool/ltfs` is where our data is. If we `cd` there, we find a `planning` directory, and within that, a `logseq` and `pages` directory. 

![image](https://github.com/user-attachments/assets/7494b3f4-ad2b-4660-9de4-457b7a364bc4)

Running `find . -type f -exec sha256sum {} + | awk '{print $1}' | sort | uniq` gets us a list of all the hashes here.

![image](https://github.com/user-attachments/assets/ace902f4-ed2c-4ded-8bae-29aff2251d21)

Challenge complete right? 

Wrong. It's not going to be that easy. 

Submitting the hashes of these files was *not* the answer. I actually got stuck for a little bit here thinking I had the solution, and didn't know where I was going wrong. I have the hashes of the files that are in the disk backup, which is seemingly all we need. What more could you want?

It wasn't until after I carefully re-read the prompt that I realized what exactly they were asking for. 

**All** SHA256 hashes that we can extract. 

We are adding the ZFS volumes incrementally, and then taking a look at the final result. What if along the way, midway through putting the ZFS volumes together, we have access to different files, or at the very least, files that have different hashes? 

I modify our bash script from earlier to essentially mount the filesystem after we add a new `logseq` file, so that we can take a look at each step of the process. In other words, taking a snapshot of the filesystem at each step as we add each `logseq` file.

```bash
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
    local filesystem_name=$2
    echo "Adding $file to pool task2pool as $filesystem_name"
    
    # Receive the snapshot into the pool as a new filesystem
    sudo zfs receive -F task2pool/$filesystem_name < "$file"
    
    # Set a mount point for the new filesystem
    local mount_dir="/mnt/task2pool/$filesystem_name"
    sudo zfs set mountpoint=$mount_dir task2pool/$filesystem_name
    
    # Mount the new filesystem
    sudo zfs mount task2pool/$filesystem_name
}

# Start with an initial file
initial_file="logseq291502518216656"

# Outer loop to handle multiple files. Loop from 1 to 20 since there are 20 logseq files
for i in {1..20}; do
    # Initialize current_file for this iteration of outer loop
    current_file="$initial_file"
    count=0  # Reset the counter for each outer loop iteration

    while [ -n "$current_file" ]; do
        if [ $count -eq $i ]; then
            break
        fi

        echo "Processing file: $current_file"
    
        # Print the file name
        echo "File name: $current_file"
    
        # Add the current snapshot file to the pool as a new filesystem
        add_to_pool "$current_file" "snapshot_$i"
    
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
        
        ((count++))  # Increment the counter
    done
done
```

In the script, I mounted everything in `/mnt/task2pool`. If we go there and run `ls`, we see:

![image](https://github.com/user-attachments/assets/228fe1bf-d9f6-412d-aae6-e6a79fcaf53f)

And sure enough if we run `ls -lR` (this being a small snippet of the output)

![image](https://github.com/user-attachments/assets/261a16f3-d37e-4c2f-a926-1402b0405538)

At nearly each step of the process, each snapshot has its own set of files, which may very well have their own hashes.

Running `find . -type f -exec sha256sum {} + | awk '{print $1}' | sort | uniq` will print them all to the console for us, resulting in a pretty long output of sha256 hashes. Waaaay longer than what we had before:

```
00d0d281c60c8abc7a78dea8be550b838555651f1c84b9629eb972ab373178b1
0409752c2490cbc8dd02208990d1cf54a619095766ebb5c28aa9af9f2c2d7cff
0691ef7bdda133ccfe7121ebd7cc470e76cbfed92f3ba6d7beef395b2618b1b7
0b7f06a779afd2c408b3949bd37827d7280710fdbecb68b19c79ae98d004db88
0b833f977a126d35858a16ab6df8dd09855e9669f9f24ff2348e44d861a17d59
0b88abca1862864b9b7686d2a065ffd07ef9572a72ae31caefb0636ccbb31f97
0e24142e652d5bc6b3d958756d5e5025fb6e9aef48fa1e9dbddfddc3fe7cdde7
106dc2f1806f113a860d270ff0203a9f65fdc6d4a5f0b9d8bf661b0cb07f28fb
1607fe4cef2704de242f18b020b3967887ed0b0e427619ffdb96da35e9e28010
165ffb243fda5f25c78c87aeca8d6b867e94240f027856273f9e9927dda5571e
...
...
Over 100 hashes
...
...
```

And submitting this gets us our second badge!

**Results:**
>That is correct!
