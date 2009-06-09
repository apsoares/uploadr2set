# uploadr2set

**Upload2Set**  é uma alteração a uma script python que faz o upload de imagens de uma determinada directoria para a sua conta do [Flickr](http://flickr.com/).

É uma script original de [Cameron Malleroy](http://berserk.org/uploadr/) e mais tarde extendida por [Raphael Schiller](http://www.schiller.cc/blog/programming/uploadr2setpy/).

No entanto, não estando satisfeito com os resultados da mesma realizei uma série de pequenas alterações, a saber:

* Baseado no trabalho de Davide Cassenti, implementei o sistema de locking para prevenir que haja duas execuções simultâneas da script;
* Ainda, usando o trabalho de Davide Cassenti, alterei a forma como é escrita a informação para histórico. Agora, sempre que um ficheiro é gravado com sucesso para o flickr é, actualizado o ficheiro de histórico. Desta forma é possível parar o processo de upload sem se perder o histórico anterior dessa sessão.
* Implementação de um sistema simples para ignorar determinadas directorias. Se uma directoria contiver um ficheiro chamado “ignore.dir“, todas as fotos nessa directoria serão descartadas. Desta forma é possível varrer toda a minha colecção e descartar uma série de fotos que já tinha no flickr.

**Update 09/06/2009**: Alertado por um utilizador no twitter reparei que a biblioteca md5 foi substituida pela hashlib. Sendo assim, fiz as seguintes substituições:

```# import sys, time, os, urllib2, shelve, string, xmltramp, mimetools, mimetypes, md5, webbrowser, urllib
import sys, time, os, urllib2, shelve, string, xmltramp, mimetools, mimetypes, hashlib, webbrowser, urllib``` 

e

```
# APS - BEGIN - 2009/05/12 - Change md5 to hashlib
# return md5.new( f ).hexdigest()
return hashlib.md5(f).hexdigest()
# APS - END - 2009/05/12 - Change md5 to hashlib
```

Este código estava originalmente disponível no meu blog pessoal em [http://planetasoares.com](http://planetasoares.com/projectos/uploadr2set/)

---

**English:**

Uploadr2Set is a python-script that uploads images located in a certain directory to flickr.

It was originally written by [Cameron Malleroy](http://berserk.org/uploadr/). Unfortunately Cameron’s version wasn’t able to create new sets out of existing subdirectories, so [Raphael Schiller](http://www.schiller.cc/blog/programming/uploadr2setpy/) extended that away.

However, not satisfied with the results, I made some small changes to it:

* Based in Davide Cassenti’s work, I implemented a simple locking mechanism. That way if the script is already running it will exit with an error message on the screen.
* Still based in Davide’s work, I changed the way that history file is saved. Citing Davide: “The history file is now opened and closed for each upload. This makes the script slower, but in case of failure (such as a kill), we avoid the problem to have an inconsistent history file.
* Last, but not least, I implemented an ignore signal, directory based. Now, if an `ignore.dir` file exists in a directory, all images in that directory will be ignored and not uploaded to Flickr. This way I can now upload some of my missing files to flickr without duplicating images that are already there.

**Update 09/06/2009**: Alerted by an twitter user that my code didn’t work anymore, I made the necessary changes and changed md5 library to the new one hashlib. The changes are:

```# import sys, time, os, urllib2, shelve, string, xmltramp, mimetools, mimetypes, md5, webbrowser, urllib
import sys, time, os, urllib2, shelve, string, xmltramp, mimetools, mimetypes, hashlib, webbrowser, urllib```

and

```
# APS - BEGIN - 2009/05/12 - Change md5 to hashlib
# return md5.new( f ).hexdigest()
return hashlib.md5(f).hexdigest()
# APS - END - 2009/05/12 - Change md5 to hashlib
```

This code was originaly available in my personal blog in [http://planetasoares.com](http://planetasoares.com/projectos/uploadr2set/)
