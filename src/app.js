var express = require('express');
var fs = require('fs');

var sys = require("sys");
var assert = require('assert');

var _ = require('underscore');

var child_process = require('child_process');

var Future = require('fibers/future'), wait = Future.wait;
var Fiber = require('fibers');

var fs = require('fs');

(function () {
    var app = express();
    
    app.set('views', __dirname + '/../views');
    app.engine('html', function(filePath, options, callback) {
        fs.readFile(filePath, function(err, content) {
            var compiled = _.template(content);
            return callback(null, compiled(options));
        });
    });
    app.set('view engine', 'html');
    
    app.use("/static", express.static(__dirname + '/static'));
    
    var generated_dict_dir ="/tmp/password-generator";
    var default_slug = "en";
    var languages = {
        "en": {
            "name": "English",
            "in_wordlist": "/usr/share/dict/american-english",
            
            "strings": {
                "title": "Password Generator",
                "reload": "reload for more",
                "methods": [
                    "8 character alphanumeric",
                    "3 dictionary words"
                ],
                "about": "about"
            }
        },
        "es": {
            "name": "español",
            "in_wordlist": "/usr/share/dict/spanish",
            
            "strings": {
                "title": "El generador de contraseñas",
                "reload": "actualizar para obtener más",
                "methods": [
                    "De 8 caracteres alfanuméricos",
                    "3 palabras de diccionario"
                ],
                "about": "about"
            }
        },
        "fr": {
            "name": "française",
            "in_wordlist": "/usr/share/dict/french",
            
            "strings": {
                "title": "Le générateur de mot de passe",
                "reload": "recharger pour plus de",
                "methods": [
                    "8 caractères alphanumériques",
                    "3 mots du dictionnaire"
                ],
                "about": "about"
            }
        },
        "it": {
            "name": "italiano",
            "in_wordlist": "/usr/share/dict/italian",
            
            "strings": {
                "title": "La password generatore",
                "reload": "ricaricare per più",
                "methods": [
                    "8 caratteri alfanumerici",
                    "3 dizionario parole"
                ],
                "about": "about"
            }
        },
        "de": {
            "name": "Deutsch",
            "in_wordlist": "/usr/share/dict/ngerman",
            
            "strings": {
                "title": "Die Passwort-Generator",
                "reload": "reload mehr",
                "methods": [
                    "8-stellige alphanumerische",
                    "3 Dictionary Wörter"
                ],
                "about": "about"
            }
        }
    };

    function rand(a, b) {
        return Math.floor(Math.random() * (1 + b - a)) + a;
    }

    var machine_readable = Future.wrap(function (lang_slug, meta, callback) {
        var num_passwords = meta.num_columns * meta.num_lines;
        child_process.exec('/usr/bin/pwgen -s -1 -N ' + num_passwords.toString(), function (error, stdout, stderr) {
            if (error) {
                callback(error);
                return;
            }
            
            callback(undefined, stdout.split('\n'));
        });
    });

    function shuffle(list) {
      var i, j, t;
      for (i = 1; i < list.length; i++) {
        j = rand(0, i);
        if (j != i) {
          t = list[i];
          list[i] = list[j];
          list[j] = t;
        }
      }
    }
    
    var get_n_words = Future.wrap(function (file, num_words, num_words_in_list, callback) {
        var sed_arg = "";
        var i;
        
        for (i = 0; i < num_words; ++i) {
            sed_arg += rand(1, num_words_in_list - 1).toString() + "p;";
        }
        
        sed_cmd = "sed -n '" + sed_arg + "' " + file;
        console.log('executing "' + sed_cmd + '"');
        child_process.exec(sed_cmd, function (error, stdout, stderr) {
            if (error) {
                callback(error);
                return;
            }
            var results = stdout.split('\n');
            results.map(function (w) { return w.trim().toLowerCase();});
            
            //console.log('in func get_n_words ' + results.join(':'));
            shuffle(results);
            
            callback(undefined, results);
        });
    });
    
    var human_readable = (function (lang_slug, meta) {
        var num_passwords = meta.num_columns * meta.num_lines;
        var passwords = [];
        var word_num, pw_num;
        var words_per_pw = meta.pw_size / 8;
        var words, pw;
        
        //console.log("getting words...");
        
        words = get_n_words(languages[lang_slug].out_wordlist, words_per_pw * num_passwords, languages[lang_slug].num_words).wait();

        //console.log("got words");
        //console.log('human_readable ' + words.join(':'));

        for (pw_num = 0; pw_num < num_passwords; ++pw_num) {
            pw = "";
            for (word_num = 0; word_num < words_per_pw; ++word_num) {
                pw = pw + words.pop();
                if (word_num < (words_per_pw - 1)) {
                    pw = pw + " ";
                }
            }
            passwords.push(pw.toLowerCase());
        }
       
        return passwords;
    }).future();
    
    function pad_pw(pw, len) {
        var start = false;
        while (pw.length < len) {
            if (start) {
                pw = " " + pw;
            }
            else {
                pw = pw + " ";
            }
            start = !start;
        }
        return pw;
    }
    
    function format_passwords(method, password_list) {
        var line, col;
        var block = "";
        
        for (line = 0; line < method.meta.num_lines; ++line) {
            for (col = 0; col < method.meta.num_columns; ++col) {
                block += method.meta.column_spacing;
                block += pad_pw(password_list[line * method.meta.num_columns + col], method.meta.pw_size);
                block += method.meta.column_spacing;
            }
            block += "\n";
        }
        return block;
    }
    
    // entropy : 40k words, 3 of em, so 40k^3. 2^15 == 32k, so roughly (2^15)^3, ie 45 bits of entropy
    // vs pw, 8 chars from 26+26+10= 62^8, roughly (2^6)^8 ie 40 bits of entropy

    var get_page_data = (function (lang_slug) {
        var methods = [
            {
                "meta": {
                    "pw_size": 8,
                    "num_columns": 8,
                    "column_spacing": " ",
                    "num_lines": 15
                },
                "func": machine_readable
            },
            {
                "meta": {
                    "pw_size": 8 * 3,
                    "num_columns": 3,
                    "column_spacing": "    ",
                    "num_lines": 25
                },
                "func": human_readable
            }
        ];
        
        var results = [];
        var i;
        for (i = 0; i < methods.length; ++i) {
            var passwords = methods[i].func(lang_slug, methods[i].meta);
            results.push(passwords);
        }
        wait(results);

        var template_data = {};
        template_data.methods = [];
        for (i = 0; i < methods.length; ++i) {
            template_data.methods.push({
                "meta": methods[i].meta,
                "password_block": format_passwords(methods[i], results[i].get())
            });
        }
        template_data.languages = languages;
        template_data.slug = lang_slug;
        template_data.title = languages[lang_slug].strings.title;
        
        return template_data;
        
    }).future();
    
    
    var cache_pages_per_lang = 10;
    var cache = {};
    var cache_filling = {}
    
    var check_cache = (function (slug) {  
        if (!cache_filling.hasOwnProperty(slug)) {
            cache_filling[slug] = true;
            console.log(new Date().toString() + ": Filling cache for " + slug + " if needed");

            while (cache[slug].length < cache_pages_per_lang) {
                var data = get_page_data(slug).wait();
                cache[slug].push(data);
                console.log(new Date().toString() + ": Added page to cache for " + slug + ", count=" + cache[slug].length.toString());
            }
            delete cache_filling[slug];
        }
    }).future();
    
    
    function render_lang(slug, req, res) {
        console.log(new Date().toString() + ": GET /" + slug + "/");
        
        var data = cache[slug].pop();
        if (!data) {
            console.log(new Date().toString() + ": Cache for request is empty, oops");
            res.send("Oops, still generating pages, try again later");
            return;
        }
        
        res.render('index.html', data);
        
        check_cache(slug).resolve(function (err) {
            if (err) {
                throw err;
            }
        });
    }

    var prune_wordlist = Future.wrap(function (in_file, out_file, callback) {
        var cmd = "/usr/bin/perl -nle 'print if /^[\\w]{4,8}$/' " + in_file + " > " + out_file;
        child_process.exec(cmd, function (error, stdout, stderr) {
            callback(error);
        });
    });

    var count_wordlist = Future.wrap(function (file, callback) {
        child_process.exec("wc -l < " + file, function (error, stdout, stderr) {
            if (error) {
                callback(error);
                return;
            }

            callback(undefined, parseInt(stdout));
        });
    });
    
    app.get('/about', function(req, res) {
        res.render('about.html', {"title": "About Password Generator"});
    });

    app.get('/', function(req, res) {
        res.redirect('/' + default_slug + '/');
    });

    
    var init_lang = (function (slug) {
        lang = languages[slug];
        console.log("Loading language " + slug + "...");
        
        lang.out_wordlist = generated_dict_dir + "/" + slug;
        prune_wordlist(lang.in_wordlist, lang.out_wordlist).wait();        
        lang.num_words = count_wordlist(lang.out_wordlist).wait();
        
        cache[slug] = [];
        check_cache(slug).wait();
        
        app.get('/' + slug + '/', function(req, res) {
            render_lang(slug, req, res);
        });
        
        console.log("...loaded with " + lang.num_words + " words, created " + cache_pages_per_lang.toString() + "-page cache");
    }).future();
    
    function init_app () {        
        Fiber(function() {
            var slug, stat;
            
            console.log(new Date().toString() + ": Password Generator started");
            
            try {
                stat = Future.wrap(fs.stat)(generated_dict_dir).wait();
            }
            catch (e) {
                fs.mkdirSync(generated_dict_dir, 0700);
            }
            
            for (slug in languages) {
                if (languages.hasOwnProperty(slug)) {
                    init_lang(slug).wait();
                }
            }
            
            app.listen(8005);
            
            console.log(new Date().toString() + ": Listening for connections");
        }).run();
    }
    init_app();

}());


