![Stack first ptr str](https://raw.githubusercontent.com/N0fix/reverseIntro/master/img/ENSIBS.png)
# Veille Cyberdéfense - Victorien Blanchard
## Sujet : Reverse engineering et exploitation de binaires

Ce rapport de veille cyber concernera le reverse engineering, et l'exploitation de binaires via des failles du type buffer overflow. Je reviendrai sur les différentes sécurités établies au fil des années pour éviter au maximum les failles de ce genre, et sur comment chacune de ces sécurités ont été contournées.
Mon premier sujet d'étude sera donc naturellement le reverse et l'analyse de code assembleur, afin d'avoir les bases nécessaires pour attaquer l'exploitation de binaires.
Seront étudiés dans l'ordre : les binaires x86, puis x86-64, puis probablement ARM, et peut être MIPS ou une autre architecture bien plus exotique.
Je m'attaquerai parallèlement à l'exploitation de binaires pour chacune de ces familles de processeurs, en expliquant les concepts généraux de chaque failles, et les spécificités à chaque familles d'assembleur.
Il est également probable que je démarre une partie sur l'analyse de code malveillant. 


# REVERSE

Dans un premier temps nous allons analyser l'architecture x86, soit l'architecture 32bits d'intel.
Il existe évidemment de nombreuses autres architectures, dont les plus connues sont : 

 - x86-64 (Architecture 64bits intel)
 - ARM
 - MISP

## Composition d'un programme

Premièrement, il faut bien comprendre comment est composé un programme. Un programme fonctionne grâce à deux parties essentielles : le processeur et la mémoire. Avant de voir comment le processeur exécute un programme, il faut analyser comment est gérée la mémoire. 
Il est important de constater que la mémoire est répartie en plusieurs segments qui ont chacun un rôle propre.
Parmi celles qui vont le plus nous intéresser : 

 - .text (Où seront situées les instructions du programme, notre "code")
 - .bss (Où seront stockées les variables globales non initialisées)
 - .data (Où seront stockées les variables globales initialisées)
 - .got et .plt (Où sont stockées les adresses de fonctions de la libC lorsque compilées dynamiquement)

Voici un exemple avec un programme tout simple expliquant les différentes sections :

```C
#include <stdio.h>
#include <stdlib.h>
//.text section from here    
char* strBss = "Hello from bss!";     //initialised -> .data section
int variable; 			      //Not initialised -> .bss section
    
void hello(char* str){
    printf("%s\n", str);
}
    
int main(char** argv, int argc){
    char* str = "Hello from the stack!";           //Will be pushed to Stack
    char* strFromHeap = malloc(sizeof(char) * 21); //Allocated on Heap
    sprintf(strFromHeap, "Hello from the Heap!");  //Putting text in strFromHeap variable
    hello(str);                                    //str is beeing pushed to the stack
    free(strFromHeap);                             //Always free() dynamically allocated var
    return 0;
}
//end of .text section 
```
En réalité, la section .text sera bien plus grande que simplement nos quelques lignes de code transformées en assembleur. En effet par exemple lorsque l’exécutable sera compilé avec gcc en temps qu’exécutable linux 32bits (ELF32), des instructions seront ajoutées au début et après le programme que l'on a écrit. Il est intéressant de remarquer que la première fonction exécutée n'est pas la fonction `main()` , mais la fonction `_start()`, qui préparera elle même les arguments pour `_libc_start_main()`, qui préparera les arguments pour la fonction `init()`, qui appellera enfin la fonction `main()` . Les arguments préparés seront les fameux ARGV, ARGC, et ENV, une variable permettant de récupérer les variables d'environnement depuis le programme.

>Le "entry point" (l'adresse écrite dans le header du fichier et qui définit l'adresse de la première instruction à executer) pointe vers la fonction `_start()`.

Ces fonctions sont d'ailleurs évidemment observables via `objdump --disassemble  notreProgamme`, qui va entièrement désassembler notre exécutable.

Une autre partie très importante de la mémoire est une partie qui est gérée dynamiquement pendant l’exécution du programme, contrairement aux sections montrées précédemment.
Il s'agit de la pile (la fameuse "Stack") et le tas ("Heap").

### Le Heap
Dans le heap seront stockées toutes les variables allouées dynamiquement par des fonctions du type `malloc()`, `calloc()`, ou encore `realloc()` (pour les fonctions les plus communes). Ces variables sont allouées pendant l’exécution du programme et sont stockées dans le Heap. Il est intéressant de constater que le Heap contient également le contenu de ENV (et donc tous les chemins des variables d'environnement).

### La Stack

Il s'agit de la mémoire la plus manipulée lors de l’exécution d'un programme. C'est ici que le programme va stocker chaque variable qu'il a besoin de manipuler (arguments de fonctions, variables locales...).
Lors de l’exécution de fonctions dans le programme, les arguments seront "push" sur cette stack, c'est à dire qu'il seront placé en haut de la pile, au dessus du dernier élément (la pile est dite "LIFO", Last In First Out). Le programme va donc empiler (=push) des éléments sur la pile (= la stack) pour les garder en mémoires, et les dépiler (=pop) lorsqu'il aura besoin de les manipuler.

### Récapitulatif de la mémoire avec un schéma et un code
Voici un schéma qui résume bien la mémoire dans un programme en plus de donner la localisation de chaque segment dans la mémoire  :

![enter image description here](https://azeria-labs.com/wp-content/uploads/2017/07/stack-part2-1.png)

```C
#include <stdio.h>
#include <stdlib.h>
//.text section from here    
char* strBss = "Hello from bss!";     //initialised -> .data section
int variable; 			      //Not initialised -> .bss section
    
void hello(char* str){
    printf("%s\n", str);
}
    
int main(char** argv, int argc){
    char* str = "Hello from the stack!";           //Will be pushed to Stack
    char* strFromHeap = malloc(sizeof(char) * 21); //Allocated on Heap
    sprintf(strFromHeap, "Hello from the Heap!");  //Putting text in strFromHeap variable
    hello(str);                                    //str is beeing pushed to the stack
    free(strFromHeap);                             //Always free() dynamically allocated var
    return 0;
}
//end of .text section 
```


## Le processeur

### Les registres en x86

En x86 on va considérer les registres suivants : 

-   EAX, ECX, EDX, EBX 
>EAX (Accumulator) est utilisé pour stocker des valeurs en général, mais également pour stocker les valeurs de retour des fonctions.
>ECX (Counter) est généralement le compteur que l'on incrémente (compteur souvent appelé `i` dans les boucles `for` en langage `C`).
>EDX (Data) Utilisé pour les opérations d'entrée/sortie.
>EBX (Base) Utilisé comme pointeur de données (c'est lui qui va pointer vers l'adresse d'un tableau par exemple).

-   ESP, EBP
> ESP  (Extended Stack Pointer) pointe toujours vers le haut de la pile.
> EBP (Extended Base Pointer) est un pointeur qui est censé pointer vers le bas de la pile (on verra que cela n'est en réalité pas le cas).

-   ESI, EDI
> Lors des chargement de données sur le disque, ce sont ces registres qui sont utilisés pour désigner la source et la destination des opérations.
> ESI (Extended Source Index) pointeur source.
> EDI (Extended Destination Index) pointeur destination.

-   EIP (Instruction Pointer)
> Il s'agit du registre qui pointe systématiquement sur l'instruction à exécuter par le programme. 


### La syntaxe

Il existe plusieurs façon équivalentes de représenter des opérations en assembleur. Avant toute chose, il faudra choisir la syntaxe avec laquelle on souhaite travailler. 
Les instructions sont systématiquement formées d'une opération à effectuer, d'une source et d'une destination.
Par exemple, dans l'instruction `mov eax, 1`, l'opérateur `mov` déplace la valeur 1 (source) dans la destination `eax`. 

Il existe deux syntaxes équivalentes majeures, la **AT&T** et la **INTEL**, chacune comportant ses caractéristiques.
Le mot syntaxe **équivalente** est important, car il signifie qu'il est possible d'écrire une même instruction de plusieurs façons différentes.

La syntaxe **INTEL** fonctionne en : `opération <destination> <source>`
Tandis que la syntaxe **AT&T** fonctionne en : `opération <source> <destination>`

|    INTEL   | AT&T         |
|:----------:|--------------|
| mov eax, 1 | mov $1, %eax |

Une autre différence majeure entre les deux syntaxes est visible sur l'exemple ci-dessus : en **AT&T** un `%` doit être placé devant le nom des registres, et un `$` sera placé avant les valeurs.
Aussi, il est possible en assembleur de ne manipuler qu'une partie d'un registre plutôt que l’entièreté d'un registre.
En **AT&T**, désigner la partie du registre dans lequel on veut travailler se fera dans l'instruction, tandis qu'en **INTEL** cela sera défini par le nom du registre.

|    INTEL   | AT&T         |
|:----------:|--------------|
| mov al, 5 | movb $5, %eax|

En INTEL, un registre est divisible en sous parties. Par exemple, on peut utiliser le registre `EAX` différemment en l'appelant de différentes façons : 
 - EAX pour utiliser les 32 bits du registre
 - AX pour utiliser les 16 premiers bits
 - AL pour utiliser les 8 premiers bits (de 0 à 7)
 - AH pour utiliser les bits 7 à 15 

**AT&T** utilisera une syntaxe différente pour manipuler des parties de registres.
Il faudra ajouter une lettre à la fin de chaque instruction pour spécifier la taille voulue, parmi :

 -  b = byte (8 bits)
-   s = short (16 bits)
-   w = word (16 bits)
-   l = long (32 bits)

Ainsi, dans l'exemple 

|    INTEL   | AT&T         |
|:----------:|--------------|
| mov al, 5 | movb $5, %eax|

INTEL fait un déplacement vers les 8 premiers bits du registre `eax` en appelant le registre `al`, là où **AT&T** utilisera l'opération `movb`, où `b` signifiera `byte`.

Lorsque l'opération ne porte pas sur un registre mais sur une adresse, **INTEL** utilisera la syntaxe suivante :

|    INTEL   | 
|:----------:|
| mov DWORD PTR [addresse], 5 |

Pour le reste de ce rendu, j'utiliserai la syntaxe **INTEL**, le format `opération <destination> <source>` étant bien plus instinctif pour moi, car très proche de ce qui est fait pour assigner des valeurs à des variables dans des langages de programmation de plus haut niveau.

### Les instruction essentielles

Voici donc les instructions les plus courantes et dont on aura besoin afin d'expliquer la partie suivante sur les appels de fonctions.

#### MOV
L'instruction `mov <destination> <source>` copie (et ne déplace pas comme son nom pourrait l'indiquer) une valeur de la source vers la destination. Exemple : `mov eax, 1` place la valeur 1 dans `eax`.
#### ADD
L'instruction `add <destination> <source>` additionne une valeur de la source avec la destination, et copie le résultat dans la destination. Exemple si `eax` contient la valeur 10 : `add eax, 5` aura pour effet de copier la valeur 15 dans `eax`.
#### SUB
Même chose que pour l'instruction `add`, mais en soustrayant.
#### PUSH
L'instruction `push <source>` empile la valeur source sur la pile. Exemple si la `eax` vaut 15 : la valeur 15 sera placée en haut de la pile. La valeur du registre `esp` sera également modifiée puisque la taille de la pile augmente.
>Rappel : le registre `ESP` pointe systématiquement vers le haut de la pile. 

![Stack first ptr str](https://raw.githubusercontent.com/N0fix/reverseIntro/master/img/stack6.png)

#### POP
L'instruction `pop <destination>` dépile la dernière valeur sur la pile et place cette valeur dans la destination. Exemple si la valeur 15 est présente sur la pile : `pop eax` aura pour effet de retirer 15 de la pile et de placer 15 dans `eax`. La valeur du registre `esp` sera également modifiée puisque la taille de la pile réduit.

![Stack first ptr str](https://raw.githubusercontent.com/N0fix/reverseIntro/master/img/stack8.png)

#### JMP
L'instruction `jmp <addr>` permettra au programme de sauter directement à l'instruction située à l'adresse donnée. Exemple, dans ce code  :

```C
	...
   0x08048439 <+9>:	mov    DWORD PTR [esp+0x1c],0x80484f0
   0x08048441 <+17>:	mov    eax,DWORD PTR [esp+0x1c]
	...
```
Où que l'on soit dans le code, appeler `jmp 0x08048439` permettra de faire continuer le programme à partir de l'instruction :
```C
   0x08048439 <+9>:	mov    DWORD PTR [esp+0x1c],0x80484f0
```
Cette instruction est un équivalent des `GOTO` en C.

## Les appels de fonctions

### Passage des arguments et appel de la fonction

Afin de comprendre comment sont passés les arguments et comment est appelée une fonction, je vais prendre pour exemple le programme suivant :

```C
#include <stdio.h>
void hello(char* str){
    printf("%s\n", str);
}

int main(void){
    char* str = "Hello";
    hello(str);
    return 0;
}
```
Une fois la fonction `main()` désassemblé avec `GDB` via la commande `disas main`, on obtient ceci :

```C
	...
   0x08048439 <+9>:	mov    DWORD PTR [esp+0x1c],0x80484f0
   0x08048441 <+17>:	mov    eax,DWORD PTR [esp+0x1c]
   0x08048445 <+21>:	mov    DWORD PTR [esp],eax ;push addr de la string
   0x08048448 <+24>:	call   0x804841d <hello>   ;call de la fonction hello
	...
```
Trois instructions ici vont permettent de 'push' le pointeur vers notre chaîne de caractères "Hello" sur la pile.

 1. Le pointeur est placé dans la pile à l'adresse `esp+0x1c`
 2. On copie le pointeur dans `EAX`
 3. On "push" `EAX` en déplaçant son contenu sur le haut de la stack 

Théoriquement un simple `push 0x80484f0` aurai pu suffire, mais le code assembleur n'est pas toujours parfaitement optimisé. 
Voici le nouvel état de la pile : 

![Stack first ptr str](https://raw.githubusercontent.com/N0fix/reverseIntro/master/img/stack1.png)

Maintenant que notre pointeur `char* str` a bien été push sur la stack, on sait que les arguments sont prêts, on va pouvoir appeler la fonction grâce à l'instruction `call`.
L'instruction `call` est un peu particulière, car avant d'appeler la fonction, elle va push l'instruction à exécuter quand la fonction appelée sera terminée. 
Dans notre cas on avait : 
```C
	...
   0x08048448 <+24>:	call   0x804841d <hello>
   0x0804844d <+29>:	mov    eax,0x0
	...
```
L'adresse `0x0804844d` va donc être push sur la stack. On obtient : 

![Stack first ptr str](https://raw.githubusercontent.com/N0fix/reverseIntro/master/img/stack2.png)


Ensuite, le programme exécute un `jmp 0x804841d`, donc un jump à l'adresse de notre fonction `hello()`.

### Après l'appel

Une chose à savoir pour les appels aux fonctions en assembleur, c'est qu'elles doivent satisfaire deux contraintes :

 1. La fonction veut une pile rien que pour elle, elle ne veut pas savoir ce qu'il y avait déjà dans la pile avant
 2. L'état de la pile avant la fonction doit être restauré à la sortie de la fonction

Afin de répondre à la première contrainte, le programme va simuler l'idée d'une pile neuve. 
Pour faire une nouvelle pile dans notre situation, il suffirait de dire que le bas de la pile si situe désormais en haut de la pile. Ainsi, le bas et le haut de la pile étant au même niveau, on obtient une nouvelle pile vide. Afin d'être en mesure de restaurer la pile dans son état avant la fonction, on gardera juste en mémoire l'ancienne position du bas de la pile avant de dire que le bas de la pile est au même niveau que le haut de la pile.
Ceci est accompli par ces deux lignes d'assembleur que je vais détailler, et qui sont systématiquement présentes à chaque début de fonction :

```C
   0x0804841d <+0>:	push   ebp
   0x0804841e <+1>:	mov    ebp,esp
```

### L'appel à la fonction

Afin de bien comprendre ces lignes, je vais afficher l'état réel de la pile, et l'état de la pile vu par le programme après chaque instruction.

On commence par le `push ebp`
```C
   0x0804841d <+0>:	push   ebp
```
Ici, on va garder sur le haut de la stack la valeur de `ebp` avant que la fonction commence. Cela nous permettra de restaurer l'ancienne valeur d'`ebp` à la sortie de la fonction.
En rouge l'adresse de l'instruction à exécuter après la fin de la fonction `hello()` (comme décrit précédemment), en vert notre pointeur `char *str`.

![Stack first ptr str](https://raw.githubusercontent.com/N0fix/reverseIntro/master/img/stack3.png)

Deuxième instruction :
```C
   0x0804841e <+1>:	mov    ebp,esp
```
On déplace le pointeur EBP vers ESP afin d'obtenir l'impression d'une stack vide.
Le programme à donc désormais l'impression d'une pile vide : 

![Stack first ptr str](https://raw.githubusercontent.com/N0fix/reverseIntro/master/img/stack4.png)

Voici le vrai état de la pile : 

![Stack first ptr str](https://raw.githubusercontent.com/N0fix/reverseIntro/master/img/stack5.png)


### Sortie de la fonction

Les sorties de fonction sont toujours composées de deux instructions qui vont avoir pour but de remettre la pile dans l'état dans lequel elle était avant l'appel: 

```C
   0x0804842e <+17>:	leave  
   0x0804842f <+18>:	ret    
```
La première instruction `leave` est équivalent à un `pop ebp`, ce qui va rétablir EBP à son ancienne valeur : 

![Stack first ptr str](https://raw.githubusercontent.com/N0fix/reverseIntro/master/img/stack2.png) 

Tandis que l'instruction `ret`  rend la main à la fonction appelante (dans notre cas `main()`), en faisant un `pop eip` (on met l'adresse `0x0804844d` dans le registre qui pointe vers les instructions à exécuter) puis en quittant la fonction.

```C
 gdb-peda$ disas main
	... 
   0x08048445 <+21>:	mov    DWORD PTR [esp],eax
   0x08048448 <+24>:	call   0x804841d <hello>
-->0x0804844d <+29>:	mov    eax,0x0                
	...
```

Le programme lira l'instruction pointée par `eip`, et donc l'instruction qui suivait l'appel de notre fonction. 
Le programme reprends donc son cours normal.


*Passage du français à l'anglais, je traduirais le premier chapitre plus tard*

# MAIN DIFFERENCES BETWEEN x86 AND x64 ARCHITECTURE 

## First things first

The main differences between x86 and x64 (also known as x86-x64) architectures is that x86 works with 32 bytes addresses and registers, while x64 works with 64 bytes registers and memory.
This implies a few things we have to remember.

### Registers
All registers keeps the same names depending on their size (eax for 32bits, `ax` for 16bits, `al/ah` for 8bits
<!--stackedit_data:
eyJoaXN0b3J5IjpbOTMwMzE2NjM1LDE0MzQ3NDg2MTMsNzMwND
AxNDUwLDE5NDM4MzE5MDAsLTcyOTAwMzU3NSwxMDg4OTg5ODM2
LC03NTg4MjQ1MjQsNzQ5NTQ1NzAwLDEwMDkzMjUxMjMsOTQyNT
M5NjAyLDEwNjA5NTA0MzMsMTQ3MjcyNDg2LDEzNjQxOTYzMDMs
LTE1MjIyNTQ1OTcsLTExNDkwODAwOCwxMTU1Nzg0MDE2LDE2Mz
U1MzYzMzYsLTQzODc3MzMwNiwtMjA2NDE4NzU0MSwxMDUwNTMw
MzQyXX0=
-->