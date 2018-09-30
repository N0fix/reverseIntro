
# Présentation du sujet
Mon nom est Victorien Blanchard et voici mon rapport de veille cyber concernant le reverse engineering, et probablement à posteriori l'exploitation de binaire via l'étude de failles du type Buffer Overflow.
Mon premier sujet d'étude sera donc naturellement le reverse et l'analyse de code assembleur, afin d'avoir les bases nécessaires pour attaquer l'exploitation de binaire.

# REVERSE

Dans un premier temps je m’intéresse à l'architecture x86, soit l'architecture 32bits d'intel.
Il existe de nombreuses autres architectures, dont les plus connues sont : 

 - x86-64 (Architecture 64bits intel)
 - ARM
 - MISP


## Composition d'un programme

Un programme fonctionne grâce à deux parties essentielles : le processeur et la mémoire. Avant de voir comment un le processeur exécute un programme, il faut analyser comment est gérée la mémoire. 
Il est important de constater que la mémoire est répartie en plusieurs segments qui ont chacune un rôle propre.
Parmi celles qui vont le plus nous intéresser : 

 - .text (Où sera situé les instructions du programme, notre "code")
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
    return 1;
}
//end of .text section 
```
En réalité, la section .text sera bien plus grande que simplement nos quelques lignes de code transformées en assembleur. En effet par exemple lorsque l’exécutable sera compilé avec gcc en temps qu’exécutable linux 32bits (ELF32), des instructions seront ajoutées au début et après le programme que l'on a écrit. Il est intéressant de remarquer que la première fonction exécutée n'est pas la fonction `main()` , mais la fonction `_start()`, qui préparera elle même les arguments pour `_libc_start_main()`, qui préparera les arguments pour la fonction `init()`, qui appellera la fonction `main()` . Les arguments préparés seront les fameux ARGV, ARGC, et ENV, une variable permettant de récupérer les variables d'environnement depuis le programme.

>Le "entry point" (l'adresse écrite dans le header du fichier et qui définit l'adresse de la première instruction à executer) pointe vers la fonction `_start()`.

Ces fonctions sont d'ailleurs évidemment observables via `objdump --disassemble  notreProgamme`, qui va entièrement désassembler notre exécutable.

Une autre partie très importante de la mémoire est une partie qui est gérée pendant l’exécution du programme, contrairement aux sections montrées précédemment.
Il s'agit de la pile (la fameuse "Stack") et le tas ("Heap").

### Le Heap
Dans le heap seront stockées toutes les variables allouées dynamiquement par des fonctions du type `malloc()`, `calloc()`, ou encore `realloc()` (pour les fonctions les plus communes). Ces variables son allouées pendant l’exécution du programme et sont stockées dans le Heap. Il est intéressant de constater que le Heap contient également le contenu de ENV (et donc tous les chemins des variables d'environnement).

### La Stack

Lors de l’exécution de fonctions dans le programme, les arguments seront "push" sur la stack, c'est à dire qu'il seront placé en haut de la pile, au dessus du dernier élément (la pile est dite "LIFO", Last In First Out). On va donc empiler des éléments sur la stack, et les dépiler lorsque l'on en aura besoin.

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
    return 1;
}
//end of .text section 
```


## Le processeur

### Les registres en x86

En x86 on va considérer les registres suivants : 

-   EAX, ECX, EDX, EBX 

>EAX (Accumulator) est utilisé pour stocker des valeurs et pour stocker les valeurs de retour des fonctions
>ECX (Counter) est généralement le compteur que l'on incrémente (souvent appelé `i` dans les boucles `for` en langage `C`).
>EDX (Data) Utilisé pour les opérations d'entrée/sortie
>EBX (Base) Utilisé comme pointeur de données (c'est lui qui va pointer vers l'adresse d'un tableau par exemple)
-   ESP, EBP
> ESP  (Extended Stack Pointer) pointe toujours vers le haut de la pile
> EBP (Extended Base Pointer) est un pointeur qui est censé pointer vers le bas de la pile (on verra que cela n'est en réalité pas le cas)
-   ESI, EDI
> Lors des chargement de données sur le disque, ce sont ces registres qui sont utilisés pou désigner la source et la destination des opérations.
> ESI (Extended Source Index) pointeur source
> EDI (Extended Destination Index) pointeur destination
-   EIP (Instruction Pointer)
> Il s'agit du registre qui pointe systématiquement sur l'instruction à exécuter par le programme. 


### La syntaxe

Il existe plusieurs façon équivalentes de représenter des opérations en assembleur. Avant toute chose, il faudra choisir la syntaxe avec laquelle on souhaite travailler. 
Les instructions sont systématiquement formée d'une opération à effectuer, d'une source et d'une destination.
Par exemple, dans l'instruction `mov eax, 1`, l'opérateur `mov` déplace la valeur 1 (source) dans la destination `eax`. 

Il existe deux syntaxes équivalentes majeures, la A&AT et la INTEL, chacune comportant leurs caractéristiques.
Le mot syntaxe **équivalentes** est important, car il signifie qu'il est possible d'écrire une instructions de plusieurs façons différentes.

La syntaxe INTEL fonctionne en : `opération <destination> <source>`
Tandis que la syntaxe A&AT fonctionne en : `opération <source> <destination>`

Voici qu

### Les instruction essentielles

## Les appels de fonction

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

Un simple `push 0x80484f0` aurai pu suffire, mais le code assembleur n'est pas toujours parfaitement optimisé. 
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



ret2libc
ropchain
<!--stackedit_data:
eyJoaXN0b3J5IjpbMTkzNDE1OTE2OSwtNDM4NzczMzA2LC0yMD
Y0MTg3NTQxLDEwNTA1MzAzNDIsODA0NTE2OTY3LDE5MjEyNDM2
NTQsMTM4MTc0Nzg4OCwxMjI2MDU5Mjc2LDExMTgwNjE5NjUsLT
E1NzQ1MzQ1NzEsMjExNTY0NDg1OSw5NTg5MDEyNTUsNDk0NzE2
NzQyLC0xMjA2ODM5NjEsMTQ4OTIyMTY2NywyMTE5NTA1NTIzLC
0xMDY5ODg5ODc4LDIxMzUwNDM5MTUsMzg5MDEyNjM0LC03NzIw
ODkwODNdfQ==
-->