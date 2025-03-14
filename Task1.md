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
>
>Prompt:
>
>Provide the order id associated with the order most likely to be fraudulent.

### Solve:

Okay so now we're actually getting into the actual challenges. We need to find the order ID associated with the fraudulent order for this one. After downloading `shipping.db`, despite the `.db` extension, running `file` on it reveals that it is a Zip file. Let's unzip it and see what we get. 

![image](https://github.com/user-attachments/assets/92c33ad0-5226-4ad3-b326-d2a3c8a5f2ee)

We get a ton of files, most of which are unimportant:

![image](https://github.com/user-attachments/assets/f48b6011-a501-4c99-ba98-f0c7d3433bf2)

`content.xml` is what seems to actually contain the data, the issue is just visualizing it. Thankfully, just popping it into Microsoft Excel (sorry pure Linux users) does the trick. 

![image](https://github.com/user-attachments/assets/92056065-5819-4621-8ec0-9ffdd73d5789)

The spreadsheet is gigantic, with 11,550 rows. No way are we going through each row one by one. 

Briefly scrolling through the spreadsheet, there's a lot of things that are repeated, specifically emails and addresses. I figured that anything malicious would probably only show up once, so using the `UNIQUE` function in Excel, I isolated all unique entries and put them in their own column. Starting from the bottom upwards, most of the entries are order IDs, which make sense since they should be unique. However, the first odd entry when going from the bottom up is an address, `058 Flowers Square Apt. 948, Port Ryanshire, NE 05823`:

![image](https://github.com/user-attachments/assets/b8bee599-c93d-4f70-be84-7218605ff687)

It is associated with "Guardian Armaments", and is part of an entry that has an order ID of `GUA0094608`

![image](https://github.com/user-attachments/assets/2442407c-9849-4689-ab67-105890b04f90)

And when looking at all other Guardian Armaments entires, they use a different address, `0050 Fred Plaza Suite...`, with the below image being a small example

![image](https://github.com/user-attachments/assets/990e3852-c2f4-46b4-9e61-09f629b7b70f)

`058 Flowers Square Apt. 948, Port Ryanshire, NE 05823` is the only different address used by Guardian Armaments, meaning that it is likely fraudulent, and we are right!

Submitting its Order ID, `GUA0094608`, gets us our first badge

**Response:**
>Great Work! That order does look fishy...
