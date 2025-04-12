# 🐾 MeowWare - The Purrfect Malware Simulation Project 🐾

![Meow GIF](https://media1.giphy.com/media/v1.Y2lkPTc5MGI3NjExY3piMjZpdWgyZ2xydHJyOW93cXRhOHJpdTRscWd0emxvMHhtb3l2ZCZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/aNqEFrYVnsS52/giphy.gif)

## ⚠️ **For Educational Purposes Only!** ⚠️

Welcome to **MeowWare**, a collection of simulated malware programs designed to teach and demonstrate cybersecurity concepts. This is **NOT** for malicious use—it's all about learning and having fun (in a safe environment)!

---

## What's Inside? 🐱

### 😺 WhiskerCat (Ransomware Simulation)

WhiskerCat is here to show you how ransomware works (but don't worry, it's all for learning). It:
- Encrypts files with asymmetric and symmetric keys
- Creates a ransom note (because drama is important)
- Lets you "pay" to decrypt your files

```bash
# Encrypt files (test only, don't use on real data)
python WhiskerCat/whiskercat.py encrypt

# Decrypt files after "paying the ransom"
python WhiskerCat/whiskercat.py decrypt
```

---

### 🐱 StrayKitten (Worm Simulation)

StrayKitten is a curious little cat that:
- Scans networks for vulnerable machines
- Tries to brute-force SSH credentials
- Replicates itself (because kittens love to explore)

```bash
# Run in a safe, isolated environment
python StrayKitten/straykitten.py
```

---

### 🐈‍⬛ BlackCat (Trojan Simulation)

BlackCat is the sneaky one in the family. It:
- Logs your keystrokes
- Takes screenshots
- Executes commands remotely
- Evades detection like a true ninja

```bash
# Start the C&C server
python BlackCat/server.py

# Run the client (in a test environment only)
python BlackCat/blackcat.py
```

---

### 🐶 Dog (Code Obfuscator)

Ever wanted to make your code look like a cryptic mess? Dog has your back! It:
- Renames variables and functions with random gibberish
- Encrypts string literals with AES
- Preserves built-in functions (because breaking Python is no fun)

```bash
python Dog/dog.py input_file.py obfuscated_output.py
```

---

## How to Set It Up 🛠️

1. Clone this repo:
   ```bash
   git clone https://github.com/yourusername/MeowWare.git
   cd MeowWare
   ```

2. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Create a safe test environment:
   ```bash
   mkdir -p WhiskerCat/test_files
   # Add some test files here (nothing important)
   ```

---

## Important Notes 🛑

- **DO NOT** run this on real systems or networks.
- **ALWAYS** use isolated virtual machines for testing.
- **NEVER** use this for illegal activities.
- **REMEMBER**: Fish.

---

## Legal Stuff ⚖️

This project is for **educational purposes only**. Using MeowWare for malicious purposes is illegal and unethical. The creator is not responsible for any misuse.

---

## Want to Contribute? 🐾

I'll let my cat decide which PRs to accept!

![Cat gif](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExNjVjNGJzNTRlZDR1MGxkZnFkZWhmcW93Y3V3N2RwcGgyczI1OHNtaCZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/3oKIPnAiaMCws8nOsE/giphy.gif)