export const V1_SEED = Uint8Array.from(
	{ length: 74 },
	(_, i) => (i * 7 + 3) & 0xff,
);

export const V1_MESSAGE = "legacy npe1 payload, 42";

export const V1_ARMOR = `--------------------[ np encrypted message ]--------------------
TlBFMQELZNLSL6y5qEEmAuF1ZV0/u8qLBy/wXoZJQ45RlvmlNA4cn7whWkzXM7JO
WT6Huk+Kc9NyLgV1nQ5Rz1FeUxZ30V0+PcVQhDwICSJb+1uVD07QFq3hrIVM2Ejl
RH7Sk8vfof3d4jCuXs2P8j1aIuQ29t6Pq1Bl8SUEWLNVno5bdTP7AuZFHRRz3JfU
H3kopASL5eiea9FXDdRfQsouk6eX+fZFDcXSfsMosOkpCSXGLuqJ0TlGl2MG7sz6
TiIhK76bDB+CHm1x+TDdW22H/ONM5KGKez34fpVC4agZKYKrTmJ/7UviWW34PbnQ
8/6Ha+XHS/wDhssFpfvmLPBcCOnsKRGsLbvz+ZRffAqQg+j1BjFFj8BCEgA8fWoN
zrPfDYhBRciRNxKT5PVF0U6J4HXoje0I+unN42hhvHGq+zovAJSysqwQkA/sfbl6
urXj6or0pIAPIqXuFWY+9Y3SU+MxccGq2pogV+ZL/+xv4hCPRtet/LFdcuqv2sTf
TM8L8wUXeTsrzE+DdpWVS0wFWXCPjsnWKJsOfj+u7zoYGUHQCQCVEwLvDzqlkosW
13gW7siIzzByZBdXqMftN9hFdRErphxLsysJcICJYWGCydXeOJQu33dunO/a/Mis
pfWTr0GgEfmzx8VEUaLo1F3ysA0AoGmUoR64VEzWsay9f8BnKBYHIjtcy6K6Qw/j
k/E/BD5OmniIky92Ox8ctJ9q/Nyo0OMAQiaNMgsr7MANHanYV5JPBRb32SL2TYpZ
RvCkVPkolAzaQ1gP3dyRoFCNIgV5fwBeMFwnqxK3Xri0tOCikD6NcHr6IJDQUKUY
t2Ez1YHmEpJXnMJX4ATx92AJmrgqC/Vs+ykBgtZpgCNcI/iDHFWzb1y2A369xXBD
91OXC9+de2pLQ5E+27DpwyBTqknDADFIiSPffD23PYrUZmBfNWncnX9OJX6qOw95
qff0wfuAxGtW5w0VQdkOkpLl3FKjmO12rPfWtZLpOxTLfR5tnpNtJfT9PTEgx/Ec
sTHURrPoU7UngULmghY1+Alrm6XDVcr3zAu/RQEVZi1Lnwo8u+tuvnZkHhLfrRWK
Iy7D0StfpK9BvDd6Wcqe/8OKyPF+C/ugzhTRplmhL/afDO5zQR7gYD49aHBbdZfx
971H/oHtP+bk3VUyhMT/HALgxSKlAuHxEosX4J8DjpdzefmxARWMqYXkIuiifyM0
YtSW0LX3rr++QpCvOPHG1Wa0ONzOQTPe6uHLhjTTkqTtzz2e1ElGkBcj54lQuQ5y
kRuPA55IUbpPj40fXr0LK81yokH4fl4FFzVtrXJGFRx67Lus6cGObszNSaeHUziu
tsz6it0UjtJICnCZ5CgQWpJ+dldgzFBwiGbT0Scde1LrL1U/XCTUHlb9kWKZl0xe
S7NC3W7RPiniIoJ9vjCYkJ+9cEdFIIfBK6hNwfywdlnkqTHuXA9+Npqie2DzTiaf
7jqE5wAtBcbymv1+UlorFp2wFuAfXbpCpqULsAWf2nx+7Lm74Fg7inj65+EjtCA+
krgL0vR1KXFWT7VE9jbUjonuHTsCKW3dW8EuamILNzoxj3FH6pQcOZFpYuMKhaFT
BAFVOG6jQku4/F5U
----------------------------------------------------------------`;

export const V1_FILE_PLAIN = "v1 file bytes\n";

export const V1_FILE_B64 =
	"TlBFMQGfJBA77w5+KIXwVHB57NJnJGyGaLKptHs0P79/jaCscaT2WUr69YKAU9NmHKSBZ0B+KwQytz/RR5NtIQt89/eBDcxm4WfMvJHFpgYOlPv11iDy7P5x+XBaJR6kEX603ZvuYnAME39yS7x8F2s43bKndmzl05NDsrBXRh7Ysoagf6bEbrIGt82AxMpmmGuK67wEtUzWGftsEvIJtPjPIZTocya98/GOrILAhlEQyD56Aoi/z8FB1Tqd5qGXrLt34W/Gx6Hj6+ks45VRk01ckpMG+yXMecOaGvWsdPvKhjqUtnoNqC0/pJvpnmzTbpo1lOOuH/KetV7PnrH6cy2q+e9sheOHMae7sItWsZgGvEz3TGeBMYgnhiId9tXl18GqSf5PvE8FkzZQn9oPcQgplW/mElJCofgLxExy7mcAz2kflMeL0rkUK/zgfcQNTIZKvKQvPq4gPLTxiUSQHd+gukrMOhcgSdMWkRJyZBD8KtnJUn9SrJTS9FJK+harvugQp/jo3fzFnuJ+PgDIXeqIvhZzNIKTabdYDGjjwZ2EBEe0Huqh3rOcK5ZTTgP6xdevyMdBvIrn8MOuABjTpExbbqSoZVJ5h6AEWp6JPrB/rkd4OmSCZTXq/6YakdAV+XBSifqOT045hC96qSCZZh29pf+i3K17aOvhbsODkqOTPqLzHOw83JZTubI9ey912Hevdqo1pGZ9Q35mklvWsixKKCfREWnzNSscfcqCBYdHjzqg3MrfHNmneTdtFOiMa0rqZWzPBy/tPfseVSoDmcOsXQC7oBlual2akzel8WpJMKVy4c0ETQRaFs9ETIZrQuBOCve8Y7BeCg4ftdtRDp7z7GNynSFjA7ZmyZxAjhhMi2/yf21l3lkxATWfbqC4UYfFNASNplEI/WjrKnTeZ/M2UX3qS2yQBNpKWcE7DGjpwmi4Vi4WHVZtl8EcD3rcWHG5sXPhnOMvdT2v+mmTo7g9iAJKsCBDWFbOuyJLsxGecaGJ9SOXw66LMpyL49xZL7ab8WwBi0ZwxrdPq79iHXUoauR+95klh2uAh3oPmV73BHK5kGABlI6ovdI/fbkFso6lKNdpzxr6qJtuRR8BI7RTjzDULH6aivTpWfsV5TsGE6UmOSkpft16MVeasGExflhewk0hVH3bUeFutR9UckSRT0GAdZvrWUwzhK7CtGMVtaMOkiM40lrye8khxz322mx65XGUdtmVlP0Bnc6tUa/MJEM7GD/vS0tpLiluWTuCX6dPUNIZUekC+ke2gs9IRpLpFf9zVkJhcmhrAhYrcjbq56p2LVQ1bNq5xockmaPQw1MHxW9fQOCNblG3BJ9eJAIn29A2M6YD2QUkYqOpF0wUlu+Kdpa+7JK+ankZXClyWv5TMI7b9l0Z3SlPPPp5mdvnum2TVJIQ4Cr0kvN0ePc7AHYyrhp6+4QgLCVEfOLcD79kXFfkZec8FFvVKMTCI7tojYCZsAetEnARPD//rdCASaJRNtuv6utv7hXsV4z/EwJsEggQl57YI4zi+KO+3VWRz4xc/Ia0EHSVvRC+SwKUhTsMDvJev/3lqRCgUoIrY9qXbx9IjuQD5MhAXgNfEG6B";

export const V2_SEED = Uint8Array.from(
	{ length: 74 },
	(_, i) => (i * 11 + 5) & 0xff,
);

export const V2_MESSAGE = "legacy npe2 payload, 42";

export const V2_ARMOR = `--------------------[ np encrypted message ]--------------------
TlBFMgEaQDK92EQaDxVZa6a0a46kYzDhm7M0piXTmma3dc1dym4q3xih1v60AqgO
+saeY43z354jC6PCjINgov34FfSaC47EuwUNHHKApihFYZPupHHJGaqPtbiysOUG
VFfcKrYlHaXYp6ZN2ZxVKrccpk1VDKtRBKkP86aor5x39VLoL413XDaEaosTcUkJ
DLLl0hTGJzEalqBsQqaduszxKCJxp9IChP0UzsrwOgPmGjbJtqZzPAwvtET6o/s+
DOFP6CpRlOKUvKHSwXGSqXyviTiuSD1tktG602hmlfnlNMe0NbW+KETkG9qYY6n/
dztdgrSLjYsEq87VWFQnvNGZkNPaZeToaDZ2a8c9SfvQAhVuaxbtdVfD2g60ZZKG
Q5mD5NE2Fw0iCPze2lVFTIsfeJoe1GD1BI4jNYlAn/oRdx1W0cKCcpaF+CzOpftB
Ybvjpv9RHJfuSAlOZ1mk96uoB2jvC5IAbLgHyPnR5vIa7c1MxS/8QdP5L9+/Kdw5
lcXvGQvjWz/8yPQQ0o0wTIlhNagSrpTLXXYYgrmeVsCxmzB5HDeNntFQI9o9hVqt
oO8dpFvV4Wcp9WcKfMHl7Sho23egy4YlqnpbVWssFB6RryVFJQBGd/LzZ8kO8mvv
d1SblKhlryHrRRJXlg+gjJSuU0nZRU3j86CRQzmBTk3LIyORQUiEJzGKeJKypzwe
lRIf7J6nJjN52dFK4p+5CM+ex7wtimqswmFIs01u6iZjh95aSBeHY/xnRD2jbckt
jmT9wfzUk9NHUXszVtff7sr9tpc1kEzQQEGid/+r/iCeklFBKvTFWJrdQAyceoy1
u/7q8k2CHchkEhkRi102f33RCdvLPlZxvE+nEb2vmRlJJcnOL/YCR62CMLwJnR57
iIq61GEhMZJjLacw0/fMpYJladQkxQJoEOo97xtC/xM9NUiPemQjY/w9dRjR0ucn
jVEDZ0gwR+ioslnnT5QN1CAzenWMbOmT+kQApnWG2u/N/Jg7CIo0PAqSIy4vgOkn
rMjRn+P4D3puJJCTcfa3OWKDa63Qpg1hINYhfe0hXCvnMPN34W7C4b5FQDKt/gzp
njpDAM1K8P3S7iPkFeQU8l+JxE/nG4h3WT6bwNMJbagpT/er7ARpwRssCi8fyomm
wOh55qT+yAgUD/dQWD0N1YRmk+tkdUzBf+9g8dckKPr9c5ezwXnUAXERBDDCOYZa
dnVzbj+hAAO2nhlXThkLN8lm8wxD/vDkGnETlBRWskKMnijWYqnkeq+OADiiES79
oZwACaKjO7gr03H8odKLV0XlsERAbGAjauln5Pp/KISHdAd1VKmuQdUROgZgV7E2
utLNqZziu+lnbzXOTPbI8CX3/3eWZW9glVzghNeYXDNNdekjkB0Tz4yxAmtguRr/
LUnguduIxSK8aKdnG12GLWTpnhTgc7d6TZUh59j+tA/2aH1CQg2N/nf4nqLsNP9u
TATXMrVaSy2G6UsCD+SgXBagmCtzrum2rfyH7mvfXbosV8rLLul0RqSSZZECyfiE
61I68EtYCQQIuaOBHwgNB7txXodeAdT+PwTCkpyFl4S+1mrJ+qPILUe094DPijdb
VoPZ6BE5EF8wGK3F
----------------------------------------------------------------
`;
