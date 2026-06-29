This is the final implementation for the SAST Multi Agent Tool
For setting the API keys refer API_keys.md

# VulScan- LT
This is actually a fully Static Application Security that is quite powerful and efficient for finding vulneribilites in real world codebases, for the current implementation it is checking for vulneribilties associated with individual and not when a function is defined somewhere and used somewhere else.
The project has two core operational modes:
1. Basic Evaluation Mode -- Benchmarks multiple LLMs against codes using various prompt engineering strategies for vulneribilty detection and CWE classification.
2. Multi-Agent Analysis Mode -- A sophisticated three-stage pipeline (Discovery -> Skeptic -> Attack Chain) where specialized LLM agents collaborate to find, validate, and chain security vulnerabilities in source code.
It consists of two modes:
1 Either one can utilize the CLI mode for running the tool, which consumes a bit less resources and is a bit more focused towards the more tech savy people and better integration with other tools.
2 The other usage could be actually running the streamlit application that is designed for its elegance and its ease of use.
It provides the users a easy to use tool for scanning their source code files for the analysis


## Flow of the code
1. Load BenchVul dataset (or user-provided code) via data/loader.py or data/dir_scanner.py

2. Optionally retrieve CWE definitions via RAG (rag/cwe_index.py) using FAISS + CodeBERT embeddings

3. Build prompt using one of 7 strategies from prompts/templates.py

4. Send to LLM via one of 5 provider clients from models/

5. Parse LLM response via eval/parser.py

6. Compute metrics via eval/metrics.py

7. Save per-sample CSVs and summary tables

One important thing to note is that for our analysis the RAG did not yield any improvements over the security_audit and the chain_of_thought prompt so we are not using it as a primary tool but it still exists and is also consuming the resources, for the removal of this just follow the file RAG_remove.md in the current github repository

## File Strucuture
The file structure is as follows:
1 app.py: This is the streamlit frontend for the web application for running the tool

2 main.py: This is the CLI entry point of the tool if someone prefers doing things using the CLI interface.

3 requirements.txt: This consists of the dependencies required for the running of the tool.

4 size_reduction: This is basically a overview of how could one reduce the resource overhead if it is required to do so

5 models/: This consists the code for making api requests to the models for the working.

6 agents/: This basically consists the codes for the multi-agent mode of the tool.

7 data/: Consists the directory searching and the benchvul dataset evaluation for the testing phase(not at all required) we can remove this once we are done testing this tool.

8 eval/: This basically consists the codes that will be utilized for the analysis of the output of the code.

9 Samples/: Here some real world samples would be added for some specific CWEs and the multiagent output would be added here in the near future

10 rag/: Just used for RAG prompt if you are actually using you can save a significant memory space if you are not using this in dependencies 

The prompting is quite vastly covered in the project report in detail

## Features
1 Multi-Agent Architecture: The 3-agent pipeline (Discovery -> Skeptic -> Attack Chain) mirrors real-world security review workflows. Each agent is optimized for a different objective (recall vs. precision vs. reasoning).

2 Extensive Prompt Engineering: 7 carefully designed single-model prompts, each addressing known biases (especially CWE-89 SQL injection bias)

3 Auto-Fallback Model Client: The AutoModel class chains multiple API providers, automatically falling back on failure

4 Dual Interface: Full CLI with argparse and Streamlit web app sharing the same pipeline code, ensuring consistency.

5 Severity Classification: The multi-agent pipeline assigns overall severity (Critical/High/Medium/Low/None) with color-coded badges in the UI.

6 Interactive Q&A: The Streamlit app includes a chatbot that can answer questions about analysis results using any configured LLM, creating an interactive analysis experience.
