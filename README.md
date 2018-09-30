
# Présentation du sujet
Mon nom est Victorien Blanchard et voici mon rapport de veille cyber concernant le reverse engineering, et probablement à posteriori l'exploitation de binaire via l'étude de failles du type Buffer Overflow.
Mon premier sujet d'étude sera donc naturellement le reverse et l'analyse de code assembleur, afin d'avoir les bases nécessaires pour attaquer l'exploitation de binaire.

# REVERSE

Dans un premier temps je m'interesse à l'architecture x86, soit l'architecture 32bits d'intel.
Il existe de nombreuses autres architectures, dont les plus connues sont : 

 - x86-64 (Architecture 64bits intel)
 - ARM
 - MISP


## Composition d'un programme

Un programme fonctionne grâce à deux parties essentielles : le processeur et la mémoire. Avant de voir comment un le processeur execute un programme, il faut analyser comment est gérée la mémoire. 
Il est important de constater que la mémoire est répartie en pluieurs segments qui ont chacunes un rôle propre.
Parmi celles qui vont le plus nous intéresser : 

 - .text (Où sera situé les instructions du programme, notre "code")
 - .bss (Où seront stockées les variables globales non initialisées)
 - .data (Où seront stockées les variables globales initialisées)
 - .got et .plt (Où sont stockées les adresses de fontions de la libC lorsque compilées dynamiquement)

Voici un example avec un programme tout simple expliquant les différentes sections :

```C
#include <stdio.h>
#include <stdlib.h>
//.text section from here    
char* strBss = "Hello from data!"; //initialised -> .data section
int variable; //Not initialised -> .bss section
    
void hello(char* str){
    printf("%s\n", str);
}
    
int main(char** argv, int argc){
    char* str = "Hello from the stack!"; //Will be pushed to Stack
    char* strFromHeap = malloc(sizeof(char) * 21); //Allocated on Heap
    sprintf(strFromHeap, "Hello from the Heap!");
    hello(str);
    free(strFromHeap); //Always free() dynamically allocated var
    return 1;
}
//end of .text section 
```
En réalité, la section .text sera bien plus grande que simplement nos quelques lignes de code transformées en assembleur. En effet par exemple lorsque l'executable sera compilé avec gcc en temps qu'executable linux 32bits (ELF32), des instructions seront ajoutées au début et après le programme que l'on a écrit. Il est intéressant de remarquer que la première fonction executée n'est pas la fonction `main()` , mais la fonction `_start()`, qui préparera elle même les arguments pour `_libc_start_main()`, qui préparera les arguments pour la fonction `init()`, qui appelera la fonction `main()` . Les arguments préparés seront les fameux ARGV, ARGC, et ENV, une variable permettant de récupérer les variables d'environnement depuis le programme.

>Le "entry point" (l'adresse écrite dans le header du fichier et qui définit l'adresse de la première instruction à executer) pointe vers la fonction `_start()`.

Ces fonctions sont d'ailleurs évidemment observables via `objdump --disassemble  notreProgamme`, qui va entièrement désassembler notre executable.

Une autre partie très importante de la mémoire est une partie qui est gérée pendant l'execution du progamme, contrairement aux sections montrées précédemment.
Il s'agit de la pile (la fameuse "Stack") et le tas ("Heap").

### Le Heap
Dans le heap seront stockées toutes les variables allouées dynamiquement par des fonctions du type `malloc()`, `calloc()`, ou encore `realloc()` (pour les fonctions les plus communes). Ces variables son allouées pendant l'execution du programme et sont stockées dans le Heap. Il est intéressant de constater que le Heap contient également le contenu de ENV (et donc tous les chemins des variables d'environnement).

### La Stack

Lors de l'execution de fonctions dans le programme, les arguments seront "push" sur la stack, c'est à dire qu'il seront placé en haut de la pile, au dessus du dernier élément (la pile est dite "LIFO", Last In First Out). On va donc empiler des éléments sur la stack, et les dépiler lorsque l'on en aura besoin.

### Récap de la mémore avec un schéma + code
Voici un schéma qui résume bien la mémoire dans un programme en plus de donner la localisation de chaque segment dans la mémoire  :
![enter image description here](https://azeria-labs.com/wp-content/uploads/2017/07/stack-part2-1.png)
```C
#include <stdio.h>
#include <stdlib.h>
//.text section from here    
char* strBss = "Hello from bss!"; //initialised -> .data section
int variable; //Not initialised -> .bss section
    
void hello(char* str){
    printf("%s\n", str);
}
    
int main(char** argv, int argc){
    char* str = "Hello from the stack!"; //Will be pushed to Stack
    char* strFromHeap = malloc(sizeof(char) * 21); //Allocated on Heap
    sprintf(strFromHeap, "Hello from the Heap!");
    hello(str); //sr is beeing pushed to the stack
    free(strFromHeap); //Always free() dynamically allocated var
    return 1;
}
//end of .text section 
```


## explication differentes syntaxes assembleur
//to

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
   0x08048445 <+21>:	mov    DWORD PTR [esp],eax ;push de l'addr de la string
   0x08048448 <+24>:	call   0x804841d <hello>   ;call de la fonction hello
	...
```
Trois instructions ici vont permettrent de 'push' le pointeur vers notre chaine de caractères "Hello" sur la pile.

 1. Le pointeur est placé dans la pile à l'adresse `esp+0x1c`
 2. On copie le pointeur dans `EAX`
 3. On "push" `EAX` en déplacant son contenu sur le haut de la stack 

Un simple `push 0x80484f0` aurai pu suffire, mais le code assembleur n'est pas toujours parfaitement optimisé. 
Voici le nouvel état de la pile : 

![Stack first ptr str](https://raw.githubusercontent.com/N0fix/reverseIntro/master/img/stack1.png)

Maintenant que notre pointeur `char* str` a bien été push sur la stack, on sait que les arguments sont prêts, on va pouvoir appeler la fonction grâce à l'instruction `call`.
L'instruction `call` est un peu particulière, car avant d'appeler la fonction, elle va push l'instruction à executer quand la fonction appelée sera terminée. 
Dans notre cas on avait : 
```C
	...
   0x08048448 <+24>:	call   0x804841d <hello>
   0x0804844d <+29>:	mov    eax,0x0
	...
```
L'adresse `0x0804844d` va donc être push sur la stack. On obtient : 

![Stack first ptr str](https://raw.githubusercontent.com/N0fix/reverseIntro/master/img/stack2.png)


Ensuite, le programme execute un `jmp 0x804841d`, donc un jump à l'adresse de notre fonction `hello()`.

### Après l'appel

Une chose à savoir pour les appels aux fonctions en assembleur, c'est qu'elles doivent satisfaire deux contraintes :

 1. La fonction veut une pile rien que pour elle, elle ne veut pas savoir ce qu'il y avait déjà dans la pile avant
 2. L'état de la pile avant la fonction doit être restauré à la sortie de la fonction

Afin de répondre à la première contrainte, le programme va simuler l'idée d'une pile neuve. 
Pour faire une nouelle pile dans notre situation, il suffirait de dire que le bas de la pile si situe désormais en haut de la pile. Ainsi, le bas et le haut de la pile étant au même niveau, on obtient une nouvelle pile vide. Afin d'être en mesure de restaurer la pile dans son état avant la fonction, on gardera juste en mémoire l'ancienne position du bas de la pile avant de dire que le bas de la pile est au même niveau que le haut de la pile.
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
En rouge l'adresse de l'instruction à executer après la fin de la fonction `hello()` (comme décrit précédemment), en vert notre pointeur `char *str`.

![Stack first ptr str](https://raw.githubusercontent.com/N0fix/reverseIntro/master/img/stack3.png)

Deuxième instruction :
```C
   0x0804841e <+1>:	mov    ebp,esp
```
On déplace le pointeur EBP vers ESP afin d'obtenir l'impression d'une stack vide.
Le progamme à donc désormais l'impression d'une pile vide : 

![Stack first ptr str](https://raw.githubusercontent.com/N0fix/reverseIntro/master/img/stack4.png)

Voici le vrai état de la pile : 

![Stack first ptr str](https://raw.githubusercontent.com/N0fix/reverseIntro/master/img/stack5.png)


### Sortie de la fonction

Les sorties de fonction sont toujours composées de deux instructions qui vont avoir pour but de remettre la pile dans l'état dans lequel elle était avant l'appel: 

```C
   0x0804842e <+17>:	leave  
   0x0804842f <+18>:	ret    
```


# Lis plus à partir d'ici

Reprenons notre fonction `hello()` d'exemple : 

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
Et analysons ce qu'il se passe lors de l'appel de la foncton `hello()`.

Représentation de la pile avant l'appel à la fonction `hello()` :

|Values| Stack states |
|-----|------|
|__Some values__| __ESP__ |
|Some value||
|Some value||
|...||
|Some value||
|**Bottom of the stack**|**EBP**|

A la ligne `hello(str);` :

|Values| Stack states |
|-----|------|
|__char* str__| __ESP__ |
|Some values||
|Some value||
|Some value||
|...||
|Some value||
|**Bottom of the stack**|**EBP**|

Afin d'analyser ce qu'il se passe lors de l'appel d'une fonction, nous allons examiner le code assembleur du programme.
```C
$ gcc hello.c -o hello
$ gdb hello
gdb-peda$ disas main
   0x08048430 <+0>:	push   ebp
   0x08048431 <+1>:	mov    ebp,esp
   0x08048433 <+3>:	and    esp,0xfffffff0 ;alignement pour optimisation
   0x08048436 <+6>:	sub    esp,0x20       ;allocation de mémoire sur la pile 
   0x08048439 <+9>:	mov    DWORD PTR [esp+0x1c],0x80484f0
   0x08048441 <+17>:	mov    eax,DWORD PTR [esp+0x1c]
   0x08048445 <+21>:	mov    DWORD PTR [esp],eax ;push de l'addr de la string
   0x08048448 <+24>:	call   0x804841d <hello>   ;call de la fonction hello
   0x0804844d <+29>:	mov    eax,0x0
   0x08048452 <+34>:	leave  
   0x08048453 <+35>:	ret    
```
On remarque l'instruction `call` qui aura pour but d'appeler notre fonction `hello()`. 
Cette instruction va avoir plusieurs effets. Premièrement, elle va push l'adresse de l'instruction qui suit l'appel de la fonction (`0x000005e6` ici). Cela permettra au programme de savoir où revenir dans le code une fois la fonction `hello()` terminée.
Ensuite, elle change la valeur de l'EIP (le pointeur d'instruction) pour le faire pointer vers la première instruction de notre fonction `hello()`.

Désassemblons notre fonction `hello()` :

```C
gdb-peda$ disas hello
   0x0804841d <+0>:	push   ebp
   0x0804841e <+1>:	mov    ebp,esp               ;On prépare la pile
   0x08048420 <+3>:	sub    esp,0x18              ;On alloue de la place sur la pile
   0x08048423 <+6>:	mov    eax,DWORD PTR [ebp+0x8]
   0x08048426 <+9>:	mov    DWORD PTR [esp],eax   ;On push le pointeur vers notre chaine
   0x08048429 <+12>:	call   0x80482f0 <puts@plt>  ;Appel à la fonction puts de libc
   0x0804842e <+17>:	leave  
   0x0804842f <+18>:	ret    
```

Une fois dans la fonction `hello()`, les premières instruction auront pou but de "sauvegarder" l'état de la pile, afin de la restaurer à posteriori dans l'état dans lequel elle était avant l'appel à la fonction.
Voici l'état actuel de la pile (je rappelle que l'adresse `0x000005e6` a été push grâce à l'instruction `call` comme expliqué plus haut) :

|Values| Stack states |
|-----|------|
|0x000005e6 (value of next post function instruction)| __ESP__ |
|Some values||
|Some value||
|Some value||
|...||
|Some value||
|**Bottom of the stack (`0x0800050a`)**|**EBP**|

Le programme va executer deux instructions afin d'avoir une pile "réservée" à la fonction. C'est à dire que l'on va simuler une pile vide, qui sera utilisée pour cette fonction uniquement.
Pour simuler ça, si l'on regarde l'état de la pile, il faudrait que le bas de la pile (`EBP`) soit au même niveau que le haut de la pile (`ESP`). Pour arriver à ce résultat, une solutions est de déplacer les deux pointeurs `ESP` et `EBP` pour qu'ils pointent au même endroit. Pour un soucis pratique, on va simplement les déplacer juste au dessus de la position actuelle d'`ESP` : 

|Values| Stack states |
|-----|------|
|Valeur qui trainait dans la mémoire à cette adresse|__ESP__ et __EBP__|
|0x000005e6 (value of next post function instruction)|  |
|Some values||
|Some value||
|Some value||
|...||
|Some value||


Aux yeux du programme, la pile ressemble désormais à cela :

|Values| Stack states |
|-----|------|
|Valeur qui trainait dans la mémoire à cette adresse|__ESP__ et __EBP__|

On a réussis notre coup, on a une pile neuve, vide. Le problème c'est qu'une fois la fonction `hello()` terminée, il faudra restaurer l'état de la pile avant l'execution de la fonction. 
Pour palier à ce problème, on va juste garder en mémoire l'ancienne valeur d'`EBP` (le bas de la pile). La pile ressemble alors à cela : 

|Values| Stack states |
|-----|------|
|Old EBP adress (`0x0800050a`)|__ESP__ et __EBP__|

Ainsi, lorsque la fonction sera terminée il suffira de mettre l'ancienne adresse d'`EBP` dans `EBP`.

Tout ce qui vient d'être présenté est exactement le fonctionnement du début de la fonction `hello()` : 
```C
   0x0804841d <+0>:	push   ebp
   0x0804841e <+1>:	mov    ebp,esp
```
On observe qu'on `push ebp` afin de se souvenir de sa valeur pour la restaurer à la fin de la fonction, et enfin on dit que la nouvelle valeur du bas de la pile (EBP) est désormais le haut de la pile (ESP) (via l'instruction `mov ebp,esp` qui déplace la valeur de `ESP` dans `EBP`).

Récap : 
```C
   0x0804841d <+0>:	push   ebp
```
|Values| Stack states |
|-----|------|
|old EBP value (`0x0800050a`)|__ESP__|
|0x000005e6 (value of next post function instruction)|  |
|Some value||
|Some value||
|...||
|Some value||
|Some value|**EBP**|

```C
   0x0804841e <+1>:	mov    ebp,esp
```
|Values| Stack states |
|-----|------|
|old EBP value (`0x0800050a`)|__ESP__ et __EBP__|

<!--stackedit_data:
eyJoaXN0b3J5IjpbMTU0NjY2MzM2NiwxMzgxNzQ3ODg4LDEyMj
YwNTkyNzYsMTExODA2MTk2NSwtMTU3NDUzNDU3MSwyMTE1NjQ0
ODU5LDk1ODkwMTI1NSw0OTQ3MTY3NDIsLTEyMDY4Mzk2MSwxND
g5MjIxNjY3LDIxMTk1MDU1MjMsLTEwNjk4ODk4NzgsMjEzNTA0
MzkxNSwzODkwMTI2MzQsLTc3MjA4OTA4Myw0MTAyNDEzMzAsOT
gwMDcxMDk2LC03NTEwNDI5MjYsLTExNDk3OTQzMDhdfQ==
-->