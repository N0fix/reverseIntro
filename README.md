
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

## Les appels de fonction


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

|Valus| Stack states |
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
$ gcc hello.c -o hello -m32
$ gdb hello
gdb-peda$ disas main
...
   0x000005de <+39>:	push   DWORD PTR [ebp-0xc]
   0x000005e1 <+42>:	call   0x590 <hello>
   0x000005e6 <+47>:	add    esp,0x10
...
```
On remarque l'instruction `call` qui aura pour but d'appeler notre fonction `hello()`. 
Cette instruction va avoir plusieurs effets. Premièrement, elle va push l'adresse de l'instruction qui suit l'appel de la fonction (`0x000005e6` ici). Cela permettra au programme de savoir où revenir dans le code une fois la fonction `hello()` terminée.
Ensuite, elle change la valeur de l'EIP (le pointeur d'instruction) pour le faire pointer vers la première instruction de notre fonction `hello()`.

Désassemblons notre fonction `hello()` :

```C
gdb-peda$ disas hello
   0x00000590 <+0>:	push   ebp
   0x00000591 <+1>:	mov    ebp,esp
   0x00000593 <+3>:	push   ebx
   0x00000594 <+4>:	sub    esp,0x4
			...
   0x000005a4 <+20>:	push   DWORD PTR [ebp+0x8]
   0x000005a7 <+23>:	mov    ebx,eax
   0x000005a9 <+25>:	call   0x3f0 <puts@plt>
   0x000005ae <+30>:	add    esp,0x10
   0x000005b1 <+33>:	nop
   0x000005b2 <+34>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x000005b5 <+37>:	leave  
   0x000005b6 <+38>:	ret    
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
|**Bottom of the stack**|**EBP**|

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
|**Bottom of the stack**|**EBP**|

Aux yeux du progra
<!--stackedit_data:
eyJoaXN0b3J5IjpbLTE3OTQ5MzA5NzAsLTEwNjk4ODk4NzgsMj
EzNTA0MzkxNSwzODkwMTI2MzQsLTc3MjA4OTA4Myw0MTAyNDEz
MzAsOTgwMDcxMDk2LC03NTEwNDI5MjYsLTExNDk3OTQzMDhdfQ
==
-->