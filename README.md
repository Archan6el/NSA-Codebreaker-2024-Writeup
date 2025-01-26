# NSA-Codebreaker-2024

This is my writeup of the 2024 NSA Codebreaker Challenges

## Tasks
- [Task 0 - (Community of Practice, Discord Server)](#task-0---community-of-practice-discord-server)
- [Task 1 - No Token Left Behind - (File Forensics)](#task-1---no-token-left-behind---file-forensics)
- [Task 2 - Driving Me Crazy - (Forensics, DevOps)](#task-2---driving-me-crazy---forensics-devops)

## Task 0 - (Community of Practice, Discord Server)

**Prompt 0:**


>As a participant in the Codebreaker Challenge, you are invited to join the New Mexico Tech Codebreaker Challenge Community of Practice!
>This is the 3rd year that NMT has partnered with the NSA Codebreaker Challenge. Its purpose remains to give students interested in cybersecurity
>a place to talk about Codebreaker, cybersecurity, and other related topics.
>
>To complete this task, first, join the Discord server. https://discord.gg/SWYCM5xr4N
>
>Once there, type /task0 in the #bot-commands channel. Follow the prompts and paste the answer the bot gives you below.


Just join the CBC Discord and follow the steps ¯\_(ツ)_/¯

## Task 1 - No Token Left Behind - (File Forensics)

**Prompt 1:**


>Aaliyah is showing you how Intelligence Analysts work. She pulls up a piece of intelligence she thought was interesting. It
>shows that APTs are interested in acquiring hardware tokens used for accessing DIB networks. Those are generally controlled items,
>how could the APT get a hold of one of those?
>
>DoD sometimes sends copies of procurement records for controlled items to the NSA for analysis. Aaliyah pulls up the records but realizes
>it’s in a file format she’s not familiar with. Can you help her look for anything suspicious?
>
>If DIB companies are being actively targeted by an adversary the NSA needs to know about it so they can help mitigate the threat.
>
>Help Aaliyah determine the outlying activity in the dataset given
>
>Downloads:
>
>DoD procurement records (shipping.db)
>Prompt:
>
>Provide the order id associated with the order most likely to be fraudulent.


Okay so now we're actually getting into the actual challenges. We need to find the order ID associated with the fraudulent order for this one. Downloading `shipping.db`, I initally thought it was some kind of database file, but running `file` on it reveals that it is a Zip file. 

![image](https://github.com/user-attachments/assets/92c33ad0-5226-4ad3-b326-d2a3c8a5f2ee)

Unzipping it gives us a ton of files, most of which are unimportant:

![image](https://github.com/user-attachments/assets/f48b6011-a501-4c99-ba98-f0c7d3433bf2)

`content.xml` is what seems to actually contain the data, the issue is just visualizing it. Thankfully, just popping it into Microsoft Excel (sorry pure Linux users) does the trick. 

![image](https://github.com/user-attachments/assets/92056065-5819-4621-8ec0-9ffdd73d5789)

The spreadsheet is gigantic, with 11,550 rows. No way are we going through that by hand. 

Briefly scrolling through the spreadsheet, there's a lot of things that are repeated, specifically emails and addresses. I figured that anything malicious would probably only show up once, so using the `UNIQUE` function in Excel, I isolated all unique entries. Starting from the bottom upwards, most of the entries are order IDs, which make sense since they should be unique. However, the first odd entry when going from the bottom up is an address, `058 Flowers Square Apt. 948, Port Ryanshire, NE 05823`:

![image](https://github.com/user-attachments/assets/b8bee599-c93d-4f70-be84-7218605ff687)

It is associated with "Guardian Armaments"

![image](https://github.com/user-attachments/assets/2442407c-9849-4689-ab67-105890b04f90)

And when looking at all other Guardian Armaments entires, they use a different address, with the below image being a small example

![image](https://github.com/user-attachments/assets/990e3852-c2f4-46b4-9e61-09f629b7b70f)

`058 Flowers Square Apt. 948, Port Ryanshire, NE 05823` is the only different address used by Guardian Armamanets, meaning that is likely fraudulent, and we are right! Submitting it's Order ID, `GUA0094608` gets us our first badge

## Task 2 - Driving Me Crazy - (Forensics, DevOps)





