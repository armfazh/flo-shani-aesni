# XMSS SHA256 AVX/AVX2 Vectorized

@Author Ana Karina D. S. de Oliveira

Date: August, 2016

Compatible with **xmss-draft06**

## Changes [PR-BR]:
 - Versão ok sem erros e sem warnings
 - Sem open MP.
 - Com w fixo.
 - Pad fixo para 256 bytes.
 - Nova versão de Winternitz WOTS+
 - Com assinatura distribuída.
 - TreeTraversal para valores de árvore par e para árvore com h=5.
 - alocações de vetores no arquivo merklebib.h
 - construção da Ltree utilizando os registradores de 256 bits, gerando 8 nós da árvore ao mesmo tempo
 - sem a verificação de Winternitz. Agora somente a chave pública é verificada.
 - com o novo sha256-8simd
 - Ltree com a matriz transposta utilizando os registradores de 256
 - Assinatura utilizando os registradores de 256 bits (vetor de assinatura d de winternitz ordenado por insertion_sort)
 - com bitmasks conforme padrão draft
 - com nova versão otimizada do SHA2 (razão seq/paral = 4.5 )
 - verificação paralelizada utilizando os registradores de 256 bits (vetor de assinatura d de winternitz ordenado por insertion_sort)
 - copyvet da Ltree modificado para registradores de 256 bits
 - problemas de alinhamento corrigidos


### Usage

```bash
	$ ./xmss h w
```

where:
 - `h`: the height of the tree.
 - `w`: the Winternitz parameter.
