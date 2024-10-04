
- **SO**... I am thinking about a aptt app, implemented in ci/cd to scan the codebase for vulnerabilities, especially for golang for now, later want to do python and java / C#
    1. first thing I would like I suppose is to indentify the files, scan them against some rules and exploitation and then provide reports and feedback
   
- I mean I want this to be instalable using command line so install it using curl or something
- And I want this to when ran spin up the container and the sandbox enviroment in the virtual machine not on the clients machine (that should probably work with the ci/cd tools as github actions or what)
 
- I could implement the codebase scan as scanning just the code when ran in safe mode for possible secret coded in, dynamic sql queries and possible vulnerable function calls for xss scripting inputs from users
    -> And then I could do these things also in the attack mode so I would run the sql injection and XSS payloads against the user inputs in requests and watch for the outcomes and report afterwards
