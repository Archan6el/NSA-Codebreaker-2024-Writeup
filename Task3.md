## Task 3 - How did they get in? - (Reverse Engineering, Vulnerability Research)

**Prompt 3:**

>Great work finding those files! Barry shares the files you extracted with the blue team who share it back to Aaliyah and her team. As a first step, she ran strings across all the files found and noticed a reference to a known DIB, “Guardian Armaments” She begins connecting some dots and wonders if there is a connection between the software and the hardware tokens. But what is it used for and is there a viable threat to Guardian Armaments (GA)?
>
>She knows the Malware Reverse Engineers are experts at taking software apart and figuring out what it's doing. Aaliyah reaches out to them and keeps you in the >loop. Looking at the email, you realize your friend Ceylan is touring on that team! She is on her first tour of the Computer Network Operations Development Program
>
>Barry opens up a group chat with three of you. He wants to see the outcome of the work you two have already contributed to. Ceylan shares her screen with you as she begins to reverse the software. You and Barry grab some coffee and knuckle down to help.
>
>Figure out how the APT would use this software to their benefit
>
>
>Downloads:
>
>Executable from ZFS filesystem (server)
>Retrieved from the facility, could be important? (shredded.jpg)
>
>Prompt:
>
>Enter a valid JSON that contains the (3 interesting) keys and specific values that would have been logged if you had successfully leveraged the running software. Do ALL your work in lower case.

### Solve:
Here we go, Task 3. We're finally getting to some actual rev. 

First off, let's download the `server` executable and the `shredded.jpg` image. Opening up the image first, we are met with this:

![image](https://github.com/user-attachments/assets/91396a8d-7f82-4a49-a136-312f737a121d)

Seems to be something written on shredded paper, which was crudely put back together. It looks like it reads `JASPER_0`, or it could be `JASPER_O`. We'll keep note of it for now, and move on to the `server` executable. 

Trying to run it gives us some interesting information. 

![image](https://github.com/user-attachments/assets/36f4ab79-433a-451d-954e-e403260869e8)

We learn two key things from this. First, the `server` executable seems to be using something called `rpc`, which we can deduce from the `rpc error` message. Second, the executable needs to be able to ping some kind of auth service in order to work. 

After doing some research, `rpc` is a protocol used to call remote functions. So the `server` executable is probably trying to call some kind of ping function from an auth server. Let's pop `server` into Ghidra and Binja and see what we find. I like to use both, since in some cases, Ghidra makes it easier to see some things than Binja, and vice versa. 

After Ghidra does its analysis, we find that `server` is a Go binary. Trying to find the main function, we find a whole lot of interesting functions, but among them, two `Ping` functions

![image](https://github.com/user-attachments/assets/161b0988-4d21-4eea-8b6c-39133466fa04)

However, there isn't really anything interesting there to build off of within them, but we'll keep our eye on these `main` functions. 

After some more snooping around, I stumble upon a jackpot of interesting functions each beginning with `auth`. Since the `server` executable is trying to ping what it calls an *auth* server, we're probably in the right place. Among these functions we find what looks to be a `Ping` function, or more specifically, a `PingRequest` function. 

![image](https://github.com/user-attachments/assets/91b35027-1d2e-4318-9f49-9fa36ced77d4)
![image](https://github.com/user-attachments/assets/34702a39-7b8e-4da5-808e-6b1e152fb103)

We see some sub-functions that shed light on what parameters each function is expecting. For example, for the `AuthRequest` function, there are sub-functions called `GetPassword` and `GetUsername`, which means that it probably expects a password and username as parameters

![image](https://github.com/user-attachments/assets/b5d4da74-1977-4e9b-aff9-8bab1b202d9b)

However, the most important thing for us is the `PingRequest` function, and if we take a look, it has a `GetPing` sub-function, which means it probably expects that as a parameter. 

![image](https://github.com/user-attachments/assets/0bf781f9-44fe-4fef-919c-72c4987232c6)

We can deduce the parameters for the other functions here, and we end up with 6 that we can define. So we can start trying to make the auth server now, but how?

Since the `server` executable is in Go, we'll make the auth server in Go too. Go's implementation of the `rpc` protocol is `grpc`, and [this](https://pascalallen.medium.com/how-to-build-a-grpc-server-in-go-943f337c4e05) guide was helpful in getting started. Essentially, we first need to create a `.proto` file in which we define each of our functions, as well as their request and response parameters. That should be relatively easy to do based on what we found in Ghidra. The issue however is the `package` and `service` name that each `.proto` file needs. This is a little problematic because specifically the `service` needs to match on both the client and the server. 

Thankfully, using both Ghidra *and* Binja was pretty helpful here. If we go into the `auth/auth_grpc.(*authServiceClient).Ping` function we found in Ghidra on Binja, near the end we can see some interesting text that seems to refer to an error with a function call. 

![image](https://github.com/user-attachments/assets/795cf2ce-5327-4286-8b15-12c04c527f5d)

The text refers to `auth_service/AuthService`. `auth_service` is likely our package name, and `AuthService` is our `service` name. 

Now we have all we need, let's create our proto file. I name mine `ping.proto` since we're trying to get the ping function to work specifically, and set my `go_package` to `/seedGeneration`, since we saw some references to `seedGeneration` in those `main` functions we found earlier. The name of your proto file and `go_package` doesn't matter though. 

<details>
	<Summary> <b>Click to expand ping.proto</b> </Summary>
	
```
syntax = "proto3";

package auth_service;

option go_package = "/seedGeneration";

service AuthService {
    rpc Authenticate(AuthenticateRequest) returns (AuthenticateResponse);
    rpc Logout(LogoutRequest) returns (LogoutResponse);
    rpc Ping(PingRequest) returns (PingResponse);
    rpc RefreshToken(RefreshTokenRequest) returns (RefreshTokenResponse);
    rpc RegisterOTPSeed(RegisterOTPSeedRequest) returns (RegisterOTPSeedResponse);
    rpc VerifyOTP(VerifyOTPRequest) returns (VerifyOTPResponse);
}

message AuthenticateRequest {
    // Define fields needed for authentication
    string username = 1; // User's username
    string password = 2; // User's password
}

message AuthenticateResponse {
    // Define fields for the response
    bool success = 1;        // Indicates if authentication was successful
    string message = 2;      // Optional message for additional information
}

message LogoutRequest {
    // Define fields needed for logout
}

message LogoutResponse {
    // Define fields for the response
}

message PingRequest {
    // Define fields needed for the request
    int64 ping = 1;
}

message PingResponse {
    int64 pong = 1;
}

message RefreshTokenRequest {
    // Define fields needed for refresh token
}

message RefreshTokenResponse {
    // Define fields for the response
}

message RegisterOTPSeedRequest {
    // Define fields needed for OTP seed registration
    string username = 1;
    int64 seed = 2;
}

message RegisterOTPSeedResponse {
    // Define fields for the response
    bool success = 1;
}

message VerifyOTPRequest {
    // Define fields needed for OTP verification
    string username = 1;
    int64 otp = 2;
}

message VerifyOTPResponse {
    // Define fields for the response
    bool success = 1;
    int64 token = 2;
}
```
</details>


With our `.proto` file made, we run the `protoc` command to compile it into some Go files for us to use

`protoc --go_out=. --go-grpc_out=. ping.proto`

Now let's create the auth server. In my code, I set up some sample checks for `AuthenticateRequest` and `VerifyOTP` just to see if they do anything. Most importantly, we run the server on port 50052. 

<details>
	<Summary><b>Click to expand auth_server.go</b></Summary>
	
```Go
package main

import (
	"context"
	"fmt"
	"net"
	"google.golang.org/grpc"
	"server/seedGeneration" // Replace with the actual import path for your generated pb
)

type server struct {
	seedGeneration.UnimplementedAuthServiceServer
}

// Authenticate handles the Authenticate RPC method
func (s *server) Authenticate(ctx context.Context, req *seedGeneration.AuthenticateRequest) (*seedGeneration.AuthenticateResponse, error) {
	//fmt.Println("Authenticate request received:", req)
	// Simple logic for demonstration (you can replace it with real authentication logic)
	if req.Username == "testuser" && req.Password == "testpass" {
		return &seedGeneration.AuthenticateResponse{
			Success: true,
			Message: "Authentication successful",
		}, nil
	}
	return &seedGeneration.AuthenticateResponse{
		Success: true,
		Message: "Authentication failed",
	}, nil
}

// Logout handles the Logout RPC method
func (s *server) Logout(ctx context.Context, req *seedGeneration.LogoutRequest) (*seedGeneration.LogoutResponse, error) {
	fmt.Println("Logout request received:", req)
	// For now, just return a successful response
	return &seedGeneration.LogoutResponse{}, nil
}

// Ping handles the Ping RPC method
func (s *server) Ping(ctx context.Context, req *seedGeneration.PingRequest) (*seedGeneration.PingResponse, error) {
	fmt.Println("Ping request received:", req)
	// Simple logic for Pong response
	return &seedGeneration.PingResponse{Pong: req.Ping}, nil
}

// RefreshToken handles the RefreshToken RPC method
func (s *server) RefreshToken(ctx context.Context, req *seedGeneration.RefreshTokenRequest) (*seedGeneration.RefreshTokenResponse, error) {
	fmt.Println("RefreshToken request received:", req)
	// For now, just return a simple response
	return &seedGeneration.RefreshTokenResponse{}, nil
}

// RegisterOTPSeed handles the RegisterOTPSeed RPC method
func (s *server) RegisterOTPSeed(ctx context.Context, req *seedGeneration.RegisterOTPSeedRequest) (*seedGeneration.RegisterOTPSeedResponse, error) {
	//fmt.Println("RegisterOTPSeed request received:", req)
	// For now, just return a success response
	return &seedGeneration.RegisterOTPSeedResponse{
		Success: true,
	}, nil
}

// VerifyOTP handles the VerifyOTP RPC method
func (s *server) VerifyOTP(ctx context.Context, req *seedGeneration.VerifyOTPRequest) (*seedGeneration.VerifyOTPResponse, error) {
	fmt.Println("VerifyOTP request received:", req)
	// For now, just verify OTP logic (simple check)
	if req.Otp == 123456 {
		return &seedGeneration.VerifyOTPResponse{
			Success: true,
			Token:   654321, // Sample token
		}, nil
	}
	return &seedGeneration.VerifyOTPResponse{
		Success: false,
		Token:   0,
	}, nil
}

func main() {
	// Listen on port 50052
	lis, err := net.Listen("tcp", ":50052")
	if err != nil {
		fmt.Println("Failed to listen on port 50052:", err)
		return
	}

	// Create a gRPC server
	grpcServer := grpc.NewServer()

	// Register the AuthService server
	seedGeneration.RegisterAuthServiceServer(grpcServer, &server{})

	// Start the server
	fmt.Println("gRPC server started on port 50052")
	if err := grpcServer.Serve(lis); err != nil {
		fmt.Println("Failed to start server:", err)
	}
}
```
</details>

Let's run it with `go run auth_server.go`

![image](https://github.com/user-attachments/assets/ffccbf0f-df62-4354-b4cd-d150667b4034)

If we run the `server` executable again, we get a different result!

![image](https://github.com/user-attachments/assets/5dfd2069-54d2-4402-a3a5-1a240d47830b)
![image](https://github.com/user-attachments/assets/6cc20ad7-64a8-4122-ac65-d35ad6880360)

So now the `server` executable is starting to act like an actual server, and is hosting something on port 50051. Now we essentially have to do what we just did for the auth server but backwards. Instead of finding and defining functions for a server to respond to, we need to instead find and define functions for a client so that we can call them. Thankfully however, we've already found them. They are the `main.(*seedGenerationServer)` functions we found from earlier.

![image](https://github.com/user-attachments/assets/17899698-21b4-4bff-ad0d-da479dc0cbe9)

We can find what parameters they expect from functions beginning with `otp/seedgen`

![image](https://github.com/user-attachments/assets/cb5b4297-721a-4dff-a685-844ab86a5a78)

So for example, `GetSeed` expects a username and password

![image](https://github.com/user-attachments/assets/7e688fff-d8d7-4062-a2db-1b4225c27fa7)

What's our `package` and `service` names this time though? `package` I'll just call `seed_generation` due to the name of the `main` functions we found. We can find the `service` name in Ghidra, under `otp/seedgen`, there are a lot of functions defined with the name, `SeedGenerationService`. That's probably our `service` name.

![image](https://github.com/user-attachments/assets/1a42ff05-4152-47c7-9096-7ac4cf995b91)

Now we can make our `.proto` file! I named mine `seedGeneration.proto`

<details>
	<Summary><b>Click to expand seedGeneration.proto</b></Summary>
	
```
syntax = "proto3";

package seed_generation; 

option go_package = "/seedGeneration";

service SeedGenerationService {
   
    rpc GetSeed(GetSeedRequest) returns (GetSeedResponse);
    rpc StressTest(GetStressTestRequest) returns (GetStressTestResponse);
    rpc Ping(GetPingRequest) returns (GetPingResponse);

}

message GetStressTestRequest {
    // Define fields needed for authentication
    int64 count = 1;
}

message GetStressTestResponse {
    // Define fields for the response
    string response = 1;

}

message GetSeedRequest {
    // Define fields needed for authentication
    string username = 1;
    string token = 2;
  
}

message GetSeedResponse {
    // Define fields for the response
    int64 seed = 1;
    int64 count = 2;
}

message GetPingRequest {
    // Define fields needed for the request
    int64 ping = 1;
}

message GetPingResponse {
    int64 pong = 1;
}
```
</details>

Instead of Go, it turns out you can do `grpc` stuff in Python too. To save myself the Go setup headache, I made my client in Python. For Python, compile the proto file with

`python -m grpc_tools.protoc --proto_path=. --python_out=. --grpc_python_out=. seedGeneration.proto`

(Make sure you have installed the needed Python libraries with `pip install grpcio grpcio-tools protobuf`)

I want to call the `GetSeed` function first since it seems the most promising. However as mentioned before, it expects a username and password. What could they be?

This is where the `shredded.jpg` image comes into play. I was thinking of what `JASPER` meant, or where I've seen it before, and then I remembered Task 1. On the suspicious order, one of the emails was `jasper_04044@guard.ar`!

![image](https://github.com/user-attachments/assets/d2eda0be-aa33-4b92-9a18-b40467871f02)

`jasper_04044` is probably our username! For the password, I just went with `password` as a test. 

Let's make the client now in Python. I make some code to call `StressTest` too but I comment it out for now. I mainly want to see what `GetSeed` does. 

<details>
<Summary><b>Click to expand client.py</b></Summary>

```python
import grpc
import seedGeneration_pb2
import seedGeneration_pb2_grpc

def get_seed(stub, username, password):
    # Create the GetSeed request (add any fields if necessary)
    request = seedGeneration_pb2.GetSeedRequest(username=username, token=password)
    
    # Call the GetSeed method
    response = stub.GetSeed(request)
    
    return response

def stress_test(stub, count):
    request = seedGeneration_pb2.GetStressTestRequest(count=count)

    response = stub.StressTest(request)
    return response
    

def run():
    # Connect to the gRPC server
    with grpc.insecure_channel('localhost:50051') as channel:

        stub = seedGeneration_pb2_grpc.SeedGenerationServiceStub(channel)
        
        # Replace with your actual username and password
        
        username = "jasper_04044"
        password = "password"

        count = 1
        
        print("Send get_seed")
        response = get_seed(stub, username, password)
        print("Get seed response:")
        print(response)

        #response = stress_test(stub, count)
        #print(response)


if __name__ == "__main__":
    run()
```
</details>

If we run this, we get a response!

![image](https://github.com/user-attachments/assets/ff1a9513-8556-46f3-8bc6-cb07fecf68c5)
![image](https://github.com/user-attachments/assets/a44da953-2b4a-4e7a-a56c-ae29df9cad91)
>Note the dates being after the competition is due to me recreating the results when making this writeup

Well, `{"time":"2025-02-15T20:57:05.742357055-06:00","level":"INFO","msg":"Registered OTP seed with authentication service","username":"jasper_04044","seed":8074660958352453125,"count":1}` is some JSON, and the 3 important keys are `{"username":"jasper_04044","seed":8074660958352453125,"count":1}`. Is this our answer? I submit this, but it says that what I have isn't quite right. So we have the correct keys, just not the correct values. What to do now?

After some thinking, I remembered that the prompt was asking for the output that would be given if the attackers had "successfully leveraged" the running software. That means that they had to exploit something. Looking back at the `GetSeed` function in Ghidra, we find something interesting. 

![image](https://github.com/user-attachments/assets/fdd1ab60-129f-41bd-960c-e8eaae5ea6f7)

A call to some sort of `auth` function. If we take a look, there's a lot of logic, but one if statement stands out. 

![image](https://github.com/user-attachments/assets/1ce8996f-0ff5-42a3-b933-6b596640e735)

It's even more evident in Binja with a `test user authenticated...` message

![image](https://github.com/user-attachments/assets/21ef9c32-aa50-493c-a943-260c135b0f6c)

It seems that we have to somehow exploit the `server` executable, or its logic, in order to call this function. Well, how do we even go about doing that? First we need to see what's being passed into this function

Let's run `server` using gdb and set a breakpoint at `main.(*SeedgenAuthClient).auth`

![image](https://github.com/user-attachments/assets/6dbcf66e-feca-474d-95de-7c908c88f33f)

If we run our client and call `GetSeed`, we hit our breakpoint 

![image](https://github.com/user-attachments/assets/e7cd7a8d-c36a-4b21-b1a6-a9ca418b018f)

So username and password is passed into `auth`. Additionally, some kind of value, `c` is passed in as well to both `GetSeed` and `auth`. With the info we know right now, let's see if we can rename some variables in the `auth` function on Ghidra to make it easier to read

<details>
<Summary><b>Click to expand main.(*SeedgenAuthClient).auth</b></Summary>

```c
long main.(*SeedgenAuthClient).auth
               (long param_1,undefined8 param_2,undefined8 param_3,ulong param_4,char *param_5,
               long param_6)

{
  long *in_RAX;
  long lVar1;
  ulong uVar2;
  undefined8 *puVar3;
  ulong uVar4;
  long unaff_RBX;
  long *plVar5;
  long unaff_R14;
  uint uVar6;
  double __x;
  double dVar7;
  long *param_7;
  long param_8;
  ulong param_9;
  long param_10;
  undefined8 param_11;
  char *param_12;
  long param_13;
  undefined local_28 [16];
  undefined local_18 [16];
  
  param_7 = in_RAX;
  param_9 = param_4;
  param_8 = unaff_RBX;
  param_11 = param_2;
  param_10 = param_1;
  param_12 = param_5;
  param_13 = param_6;
  while (local_28 + 8 <= *(undefined **)(unaff_R14 + 0x10)) {
    runtime.morestack_noctxt.abi0();
  }
  param_7[3] = param_7[3] + 1;
  uVar4 = param_7[2];
  lVar1 = math/rand.Int63();
  param_7[2] = lVar1;
  runtime.convTstring();
  local_28._8_8_ = &PTR_DAT_0095c9a0;
  local_28._0_8_ = &DAT_008075e0;
  local_18._8_8_ = runtime.convTstring();
  local_18._0_8_ = &DAT_008075e0;
  dVar7 = log/slog.(*Logger).log(__x);
  if ((param_13 != 0) && (*param_12 == '\0')) {
    return param_7[2];
  }
  uVar2 = 0;
  do {
    if ((long)param_9 <= (long)uVar2) {
      if ((uint)uVar4 == 0x7032f1e8) {
        log/slog.(*Logger).log(dVar7);
        return param_7[2];
      }
      plVar5 = (long *)0x0;
      log/slog.(*Logger).log(dVar7);
      lVar1 = runtime.newobject();
      *(ulong *)(lVar1 + 0x30) = param_9;
      if (runtime.writeBarrier != 0) {
        lVar1 = runtime.gcWriteBarrier1();
        *plVar5 = param_8;
      }
      *(long *)(lVar1 + 0x28) = param_8;
      *(undefined8 *)(lVar1 + 0x40) = param_11;
      if (runtime.writeBarrier != 0) {
        lVar1 = runtime.gcWriteBarrier1();
        *plVar5 = param_10;
      }
      *(long *)(lVar1 + 0x38) = param_10;
      dVar7 = (double)(**(code **)(*param_7 + 0x18))(lVar1,0,param_7,&regexp.arrayNoInts,0,0);
      log/slog.(*Logger).log(dVar7);
      puVar3 = (undefined8 *)runtime.newobject();
      puVar3[1] = 0x16;
      *puVar3 = &DAT_008b9c8b;
      return -1;
    }
    if ((long)param_9 < (long)(uVar2 + 4)) {
      lVar1 = param_9 - uVar2;
      if (lVar1 == 1) {
        if (param_9 <= uVar2) {
                    /* WARNING: Subroutine does not return */
          runtime.panicIndex();
        }
        uVar6 = (uint)*(byte *)(param_8 + uVar2);
      }
      else if (lVar1 == 2) {
        if (param_9 <= uVar2) {
                    /* WARNING: Subroutine does not return */
          runtime.panicIndex();
        }
        if (param_9 <= uVar2 + 1) {
                    /* WARNING: Subroutine does not return */
          runtime.panicIndex();
        }
        uVar6 = (uint)*(ushort *)(param_8 + uVar2);
      }
      else if (lVar1 == 3) {
        if (param_9 <= uVar2) {
                    /* WARNING: Subroutine does not return */
          runtime.panicIndex();
        }
        if (param_9 <= uVar2 + 1) {
                    /* WARNING: Subroutine does not return */
          runtime.panicIndex();
        }
        if (param_9 <= uVar2 + 2) {
                    /* WARNING: Subroutine does not return */
          runtime.panicIndex();
        }
        uVar6 = (uint)CONCAT12(*(undefined *)(uVar2 + 2 + param_8),*(undefined2 *)(param_8 + uVar2))
        ;
      }
      else {
        uVar6 = 0;
      }
    }
    else {
      if (param_9 <= uVar2) {
                    /* WARNING: Subroutine does not return */
        runtime.panicIndex();
      }
      if (param_9 <= uVar2 + 1) {
                    /* WARNING: Subroutine does not return */
        runtime.panicIndex();
      }
      if (param_9 <= uVar2 + 2) {
                    /* WARNING: Subroutine does not return */
        runtime.panicIndex();
      }
      if (param_9 <= uVar2 + 3) {
                    /* WARNING: Subroutine does not return */
        runtime.panicIndex();
      }
      uVar6 = *(uint *)(param_8 + uVar2);
    }
    uVar4 = (ulong)((uint)uVar4 ^ uVar6);
    uVar2 = uVar2 + 4;
  } while( true );
}
```
</details>

Right off the bat, we can see that `uVar2` seems to be some kind of counter, since it starts at 0 and gets incremented by 4 each iteration. Let's rename it to `i`. 

Something interesting is `param_7`, which is set equal to `in_RAX`. This perhaps could be what `c` was pointing to? We see that `param_7[2]` is assigned to `lVar1`, which itself is assigned to a random number, `math/rand.Int63();`. Well in gdb we can see what that number is by using pointer arithmetic to essentially index `param_7[2]`. 

We hit the breakpoint again in gdb and this time get

![image](https://github.com/user-attachments/assets/e9f269a7-af86-41da-b791-a324591bf1fa)

Since `c` is probably `param_7`, let's use pointer arithmetic to get the value at `param_7[2]`. If we add 2*8 to this address, we should get the element at the index 2, since each element takes up 8 bytes. We get
 a value:

 ![image](https://github.com/user-attachments/assets/807b4eb7-42f3-4a0d-ba75-88fe285f6fa0)

 This is the number `6205117966191793308`

We get the response

![image](https://github.com/user-attachments/assets/c65b1582-92e2-4146-a5e6-646e09ec4a7e)

That didn't really tell us much, let's do another run. 

This time we get

![image](https://github.com/user-attachments/assets/17b381a2-7c74-4b3f-b8eb-97f6586ba64a)

This is the number `8074660958352453125`. Hey wait a second. That was our seed value from the last run!

This time we get this output:

![image](https://github.com/user-attachments/assets/416900b3-c1d2-4a11-9f08-8a8f37434d61)

One more run to make sure we know what's going on.

![image](https://github.com/user-attachments/assets/1b19f0c0-18ec-47e3-8a95-c5be2fcf9e58)

Sure enough, this is the number `3009302561299014827`, which was our seed from the last run. So we can confidently say that the random number generated is the seed, so we can rename `lVar1` to `seed` in Ghidra. 

The logic seems to be indexing or taking chunks of `param_8` and assigning it to `uVar6`. `param_8` is assigned to `unaff_RBX`. If we look in gdb to see what's at `rbx`, we see that it's our username

![image](https://github.com/user-attachments/assets/ebdb1ca6-a3da-43d5-b23e-1e480c33bdd5)

So `param_8` is the username, and we can change the name accordingly. We'll rename `uVar6` to `chunk`, since it's essentially a chunk of the username. 

If we look at the what dictates the loop, the loop is dependent on `i` being less than `param_9`. Well if we're taking chunks of the username each time, `param_9` is likely the length of the username, since it would stop the loop if `i` is greater than or equal to the username's length. We can change `param_9` accordingly. 

The function then Xor's the username chunk and whatever `uVar4` is. `uVar4` is checked with the value `0x7032f1e8` in each iteration to see if it equals, and then prints the `user authenticated...` message before. We'll rename `uVar4` to `target`. 

After our variable renaming, we now have this code. 

<details>
<Summary><b>Click to expand main.(*SeedgenAuthClient).auth</b></Summary>

```c
long main.(*SeedgenAuthClient).auth
               (long param_1,undefined8 param_2,undefined8 param_3,ulong param_4,char *param_5,
               long param_6)

{
  long *in_RAX;
  long seed;
  ulong i;
  undefined8 *puVar1;
  ulong target;
  long unaff_RBX;
  long *plVar2;
  long unaff_R14;
  uint chunk;
  double __x;
  double dVar3;
  long *param_7;
  long username;
  ulong username_length;
  long lStack0000000000000020;
  undefined8 uStack0000000000000028;
  char *pcStack0000000000000030;
  long lStack0000000000000038;
  undefined local_28 [16];
  undefined local_18 [16];
  
  param_7 = in_RAX;
  username_length = param_4;
  username = unaff_RBX;
  uStack0000000000000028 = param_2;
  lStack0000000000000020 = param_1;
  pcStack0000000000000030 = param_5;
  lStack0000000000000038 = param_6;
  while (local_28 + 8 <= *(undefined **)(unaff_R14 + 0x10)) {
    runtime.morestack_noctxt.abi0();
  }
  param_7[3] = param_7[3] + 1;
  target = param_7[2];
  seed = math/rand.Int63();
  param_7[2] = seed;
  runtime.convTstring();
  local_28._8_8_ = &PTR_DAT_0095c9a0;
  local_28._0_8_ = &DAT_008075e0;
  local_18._8_8_ = runtime.convTstring();
  local_18._0_8_ = &DAT_008075e0;
  dVar3 = log/slog.(*Logger).log(__x);
  if ((lStack0000000000000038 != 0) && (*pcStack0000000000000030 == '\0')) {
    return param_7[2];
  }
  i = 0;
  do {
    if ((long)username_length <= (long)i) {
      if ((uint)target == 0x7032f1e8) {
        log/slog.(*Logger).log(dVar3);
        return param_7[2];
      }
      plVar2 = (long *)0x0;
      log/slog.(*Logger).log(dVar3);
      seed = runtime.newobject();
      *(ulong *)(seed + 0x30) = username_length;
      if (runtime.writeBarrier != 0) {
        seed = runtime.gcWriteBarrier1();
        *plVar2 = username;
      }
      *(long *)(seed + 0x28) = username;
      *(undefined8 *)(seed + 0x40) = uStack0000000000000028;
      if (runtime.writeBarrier != 0) {
        seed = runtime.gcWriteBarrier1();
        *plVar2 = lStack0000000000000020;
      }
      *(long *)(seed + 0x38) = lStack0000000000000020;
      dVar3 = (double)(**(code **)(*param_7 + 0x18))(seed,0,param_7,&regexp.arrayNoInts,0,0);
      log/slog.(*Logger).log(dVar3);
      puVar1 = (undefined8 *)runtime.newobject();
      puVar1[1] = 0x16;
      *puVar1 = &DAT_008b9c8b;
      return -1;
    }
    if ((long)username_length < (long)(i + 4)) {
      seed = username_length - i;
      if (seed == 1) {
        if (username_length <= i) {
                    /* WARNING: Subroutine does not return */
          runtime.panicIndex();
        }
        chunk = (uint)*(byte *)(username + i);
      }
      else if (seed == 2) {
        if (username_length <= i) {
                    /* WARNING: Subroutine does not return */
          runtime.panicIndex();
        }
        if (username_length <= i + 1) {
                    /* WARNING: Subroutine does not return */
          runtime.panicIndex();
        }
        chunk = (uint)*(ushort *)(username + i);
      }
      else if (seed == 3) {
        if (username_length <= i) {
                    /* WARNING: Subroutine does not return */
          runtime.panicIndex();
        }
        if (username_length <= i + 1) {
                    /* WARNING: Subroutine does not return */
          runtime.panicIndex();
        }
        if (username_length <= i + 2) {
                    /* WARNING: Subroutine does not return */
          runtime.panicIndex();
        }
        chunk = (uint)CONCAT12(*(undefined *)(i + 2 + username),*(undefined2 *)(username + i));
      }
      else {
        chunk = 0;
      }
    }
    else {
      if (username_length <= i) {
                    /* WARNING: Subroutine does not return */
        runtime.panicIndex();
      }
      if (username_length <= i + 1) {
                    /* WARNING: Subroutine does not return */
        runtime.panicIndex();
      }
      if (username_length <= i + 2) {
                    /* WARNING: Subroutine does not return */
        runtime.panicIndex();
      }
      if (username_length <= i + 3) {
                    /* WARNING: Subroutine does not return */
        runtime.panicIndex();
      }
      chunk = *(uint *)(username + i);
    }
    target = (ulong)((uint)target ^ chunk);
    i = i + 4;
  } while( true );
}
```
</details>

Let's look at what it's doing. It gets a little confusing since the function initially has the `seed` variable as the randomly generated seed, assigns it to `param_7[2]`, and then reuses it later as `seed = username_length - i;`. Regardless, we can get a good grasp of what's going on. 

`target` starts as the randomly generated `seed` value. 

`target = param_7[2];`

`auth` then takes the username, and loops through it 4 bytes (characters) at a time. 

```c
 i = 0;
  do {
    if ((long)username_length <= (long)i) {
    ... Logic ...
    }
    i = i + 4;
  } while( true );
```

In each iteration, it Xor's `target` with the 4 byte chunk. 

`target = (ulong)((uint)target ^ chunk);`

After it finishes looping through the username and doing all the Xor logic, it checks to see if the final result equals `0x7032f1e8`. 

```c
if ((uint)target == 0x7032f1e8) {
	log/slog.(*Logger).log(dVar3);
	return param_7[2];
}
```
So our goal is to find the username (which we already know), seed, and count that once going through the Xor logic, will equal `0x7032f1e8`.

Technically, we could just call `GetSeed` a bunch of times, but that would take forever. The simplest way would be to recreate all this logic and run it locally. There's just one issue, which is the randomly generated number. I thought it would change each time, which would make it impossible to do locally, but after resetting the `server` executable, we can see that the seed values at the corresponding counts are the same each time

![image](https://github.com/user-attachments/assets/7c21daea-de18-4a52-98bc-62015718c8fe)

Or in other words, count 1 is always the seed 8074660958352453125, count 2 is always the seed 3009302561299014827, etc, etc every time. This means that the rando number generator is seeded, we just have to find what the seed is. 

In Ghidra, we can find the function, `math/rand.(*Rand).Seed`

![image](https://github.com/user-attachments/assets/c0aba82b-ab3a-4409-adf3-d604de833792)

Back in gdb, let's set a breakpoint there.

![image](https://github.com/user-attachments/assets/07170d5f-6c9f-447a-9eac-151af8c6b3bc)

If we run this, we immediately hit the breakpoint, and we can get our seed value!

![image](https://github.com/user-attachments/assets/0b0b4992-1cbe-4a31-b500-fe06f35a58e0)

It's `0x378f96687bfa0`

We have everything we need, let's start making our solve. We will continuously generate numbers using the seeded random number generator, take it and the username `jasper_04044`, go through the Xor logic, and check to see if it equals `0x7032f1e8`. We'll code the solve in Go since the `server` executable uses specifically Go's random number generator. 

<details>
	<Summary><b>Click to expand solve.go</b></Summary>

 ```Go
package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
)

const (
	goal uint32 = 0x7032f1e8
)


func simulateXOR(seed uint64, username string) (bool, uint64) {
    usernameBytes := []byte(username)

    uVar2 := seed // Initialize with seed value

    i := 0
   
    for i < len(usernameBytes) {
        var chunk uint32

        // Access 4 bytes at a time or less (pad smaller chunks)
        if len(usernameBytes) - i >= 4 {
            chunk = binary.LittleEndian.Uint32(usernameBytes[i : i+4])
           
        } else {
            // Process remaining bytes based on how many are left
            switch len(usernameBytes) - i {
            case 3:
                chunk = uint32(usernameBytes[i]) |
                    uint32(usernameBytes[i+1])<<8 |
                    uint32(usernameBytes[i+2])<<16
            case 2:
                chunk = uint32(usernameBytes[i]) |
                    uint32(usernameBytes[i+1])<<8
            case 1:
                chunk = uint32(usernameBytes[i])
            }
        }

        // XOR with the current chunk, casting uVar2 to uint before XORing
        //uVar2 ^= uint64(chunk) 
        uVar2 = uint64(uint32(uVar2) ^ chunk)

        // Increment by 4 for the next chunk
        i += 4
    }

    // Cast uVar2 to uint32 for the final comparison
    finalValue := uint32(uVar2)
    return finalValue == goal, uVar2
}

func main() {
	// The seed value got earlier
	seed := uint64(0x378f96687bfa0)

	// Set up the random number generator with the seed
	rand.Seed(int64(seed))

	// Username for XOR simulation
	username := "jasper_04044"

	// Start a counter to track attempts
	var attempts int64 = -1

	for {
		attempts++
		
		// Generate a new random seed value based on the original seed
		currentSeed := rand.Int63() // 63-bit random value
        
  		if attempts == 1 || attempts == 2 || attempts == 3 {
			fmt.Printf("Count %d with seed: %d\n", attempts, currentSeed)
		}

		// Simulate XOR logic with the generated random seed and username
		success, finalUVar4 := simulateXOR(uint64(currentSeed), username)
		
		if success {
			// Print seed and count if match is found
			fmt.Printf("Match found! Final uVar4: %08x\n", finalUVar4)
			fmt.Printf("Seed: %d\n", currentSeed)   // Print the seed
			fmt.Printf("Count: %d\n", attempts)  // Print the count (attempts)
			break
		}

	}
	
}

```
</details>

I print the first few attempts to see if the seed aligns with the count. We initialize `attempts` to -1, because if we start at 0, the seed will be 1 off from the count. 

Running this with `go run solve.go`, it takes a while, but eventually finishes. We get the output:

![image](https://github.com/user-attachments/assets/195f5e0e-5cc1-4d78-8c00-1b54eb51a8be)

Is this our answer?? I submit `{"username":"jasper_04044","seed":"7571067976073007827","count":"1073639578"}` but it still says it's incorrect. What the heck are we doing wrong, we have the answer right here!

It's at that point that I realized a fatal mistake I was making. 

Remember when we were using gdb to find out what was stored in `param_7[2]`, and found out that it was the seed? Remember the first number we saw was `6205117966191793308`? But instead, the *next* seed, `8074660958352453125` is what got printed. Even though `7571067976073007827` is the correct seed that along with the username would pass the Xor logic, what would get printed to the screen? The *next* seed. The prompt didn't ask for the correct seed, username, and count combo to pass the Xor logic, it asked for the correct seed, username, and count combo that would be **logged** once successfully leveraged. 

I tweak the code to print the next seed after we pass the Xor logic

<details>
<Summary><b>Click to expand solve.go</b></Summary>

 ```Go
package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
)

const (
	goal uint32 = 0x7032f1e8
)


func simulateXOR(seed uint64, username string) (bool, uint64) {
    usernameBytes := []byte(username)

    uVar2 := seed // Initialize with seed value

    i := 0
   
    for i < len(usernameBytes) {
        var chunk uint32

        // Access 4 bytes at a time or less (pad smaller chunks)
        if len(usernameBytes) - i >= 4 {
            chunk = binary.LittleEndian.Uint32(usernameBytes[i : i+4])
           
        } else {
            // Process remaining bytes based on how many are left
            switch len(usernameBytes) - i {
            case 3:
                chunk = uint32(usernameBytes[i]) |
                    uint32(usernameBytes[i+1])<<8 |
                    uint32(usernameBytes[i+2])<<16
            case 2:
                chunk = uint32(usernameBytes[i]) |
                    uint32(usernameBytes[i+1])<<8
            case 1:
                chunk = uint32(usernameBytes[i])
            }
        }

        // XOR with the current chunk, casting uVar2 to uint before XORing
        //uVar2 ^= uint64(chunk) 
        uVar2 = uint64(uint32(uVar2) ^ chunk)

        // Increment by 4 for the next chunk
        i += 4
    }

    // Cast uVar2 to uint32 for the final comparison
    finalValue := uint32(uVar2)
    return finalValue == goal, uVar2
}

func main() {
	// The seed value got earlier
	seed := uint64(0x378f96687bfa0)

	// Set up the random number generator with the seed
	rand.Seed(int64(seed))

	// Username for XOR simulation
	username := "jasper_04044"

	// Start a counter to track attempts
	var attempts int64 = -1

	for {
		attempts++
		
		// Generate a new random seed value based on the original seed
		currentSeed := rand.Int63() // 63-bit random value
        
  		if attempts == 1 || attempts == 2 || attempts == 3 {
			fmt.Printf("Count %d with seed: %d\n", attempts, currentSeed)
		}

		// Simulate XOR logic with the generated random seed and username
		success, finalUVar4 := simulateXOR(uint64(currentSeed), username)
		
		if success {
			// Print seed and count if match is found
			fmt.Printf("Match found! Final uVar4: %08x\n", finalUVar4)
			fmt.Printf("Seed: %d\n", currentSeed)   // Print the seed
			fmt.Printf("Count: %d\n", attempts)  // Print the count (attempts)
 			fmt.Printf("Next seed: %d\n", rand.Int63())
			break
		}

	}
	
}
```

</details>

This time we get the output:

![image](https://github.com/user-attachments/assets/920deca2-fa73-45ea-bb9e-7537b95f02f8)

Therefore our answer is 

`{"username":"jasper_04044","seed":"5838753747453732554","count":"1073639578"}`

And with that, we have finally solved Task 3. Took a while, huh?

**Results:**
>So that's how they leveraged their tokens!
