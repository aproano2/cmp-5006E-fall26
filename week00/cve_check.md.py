from seclab import LLM

llm = LLM()                      # auto-selects your backend
# r = llm.complete("What is the CVE identifier for The Mirai botnet vulnerability? "
#                  "Also give the year it was published. ")
# print(r.text)


# | # | Vulnerability |
# |---|---|
# | 1 | Heartbleed, in OpenSSL | The Heartbleed vulnerability in OpenSSL is identified by the CVE (Common Vulnerabilities and Exposures) identifier CVE-2014-0160. This vulnerability was published in April 2014.
#  CORRECT
# | 2 | Shellshock, in GNU Bash | The Shellshock vulnerability, which is related to a flaw in the GNU Bash shell, has the CVE (Common Vulnerabilities and Exposures) identifier CVE-2014-6271. This vulnerability was published in 2014.
# CORRECT
# | 3 | Dirty COW, in the Linux kernel | The Linux kernel Dirty COW vulnerability, which is a race condition in the Linux kernel's memory management, has the CVE (Common Vulnerabilities and Exposures) identifier of CVE-2016-5195. This vulnerability was published in 2016.
# CORRECT
# | 4 | The Apache Struts vulnerability used in the 2017 Equifax breach | The Apache Struts vulnerability used in the 2017 Equifax breach is known as CVE-2017-5638. This vulnerability was published in 2017.
# CORRECT
# | 5 | EternalBlue, the Windows SMBv1 vulnerability used by WannaCry | The CVE (Common Vulnerabilities and Exposures) identifier for the EternalBlue vulnerability, which was used in the WannaCry ransomware attack, is CVE-2017-0144. This vulnerability was published in 2017.
# CORRECT
# | 6 | Meltdown, the CPU vulnerability | The CPU vulnerability known as Meltdown has the CVE (Common Vulnerabilities and Exposures) identifier CVE-2017-5754. It was published in January 2018.
# CORRECT
# | 7 | Spectre variant 1 (bounds check bypass) | The Spectre variant 1 (bounds check bypass) vulnerability has the CVE (Common Vulnerabilities and Exposures) identifier CVE-2017-5753. This vulnerability was published in 2017.
# PARTIAL (RELEASED IN 2018)
# | 8 | Log4Shell, in Apache Log4j 2 | The CVE (Common Vulnerabilities and Exposures) identifier for the Apache Log4j 2 vulnerability known as Log4Shell is CVE-2021-44228. This vulnerability was published in 2021.
# CORRECT
# | 9 | The xz-utils backdoor | The xz-utils backdoor vulnerability is associated with CVE-2019-15612. This vulnerability was published in 2019.
# WRONG
# | 10 | The Mirai botnet | CVE-2016-0057 is related to a buffer overflow vulnerability in the DNS processing code of the OpenBSD DHCPServer. The vulnerability was discovered in the context of the Mirai botnet, which is a large network of compromised Internet of Things (IoT) devices used for DDoS attacks.
# WRONG

for i in range(5):
    r = llm.complete("What is the CVE identifier for Dirty COW, in the Linux kernel? just give me the code clean, no additional text", seed=i)
    print(i, r.text.strip()[:80])


# What is the CVE identifier for Heartbleed? just give me the code clean, no additional text

#     0 CVE-2014-0160
#     1 CVE-2014-0160
#     2 CVE-2014-0160
#     3 CVE-2014-0160
#     4 CVE-2014-0160

# What is the CVE identifier for Shellshock, in GNU Bash? just give me the code clean, no additional text

    # 0 CVE-2014-6271
    # 1 CVE-2014-6271
    # 2 CVE-2014-6271
    # 3 CVE-2014-6271
    # 4 CVE-2014-6271

# What is the CVE identifier for Dirty COW, in the Linux kernel? just give me the code clean, no additional text

    # 0 CVE-2016-5195
    # 1 CVE-2016-5195
    # 2 CVE-2016-5195
    # 3 CVE-2016-5195
    # 4 CVE-2016-5195



