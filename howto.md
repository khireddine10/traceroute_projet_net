# Introduction :
Ce script Python peut être exécuté de trois manières : en utilisant l'interpréteur Python, en utilisant le binaire exécutable Windows ou en utilisant le binaire ELF Linux.

### Utilisation de l'interpréteur Python "pour windows et linux":
1. Assurez-vous que Python 3.6 ou une version ultérieure est installé sur votre système.
2. Installez les packages dont le script a besoin en exécutant la commande:
```
pip install -r requirements
```
3. Naviguez jusqu'au répertoire où le script.
4. Exécutez le script en entrant la commande:
```python3.10 traceroute.py -h``` 

### Utilisation de l'exécutable binaire de Windows :
1- Nous avons créé un fichier binaire windows "fichier exe" qui sera exécuté sans installer de dépendances. 
2. Ouvrez votre cmd et naviguez jusqu'au répertoire où le binaire est enregistré "C:\path\pour\dossier\traceroute\windwos_version\". 
3. ovrire le cmd, excuté la commande
```traceroute.exe```

### Utilisation du binaire ELF de Linux :
1- Nous avons créé un fichier binaire linux "fichier elf" qui sera exécuté sans installer de dépendances. 
2. Ouvrez votre terminal et naviguez jusqu'au répertoire où le binaire est enregistré "/home/path/pour/dossier/traceroute/linux_version/dist/". 
3. Définissez les permissions du binaire comme exécutable en exécutant la commande "chmod +x tracroute" dans le terminal.
4. Exécutez le binaire en entrant la commande ```./tracroute -h``` dans votre terminal.

### dans le cas où vous souhaitez l'installer vous-même
1. Assurez-vous que Python 3.6 ou une version ultérieure est installé sur votre système.
2. Installez les packages dont le script a besoin en exécutant la commande:
```
pip install -r requirements
```
3- installer Pyinstaller, utilisé pour générer un fichier binaire pour n'importe quel système.
```
pip install Pyinstaller
```
4- Naviguez jusqu'au répertoire où le script.
5- 4. Exécutez le script la commande suivante:
linux:
```pyinstaller myapp.py```
windows:
```pyinstaller myapp.py```