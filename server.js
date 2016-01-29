/* Módulos requeridos por la aplicación */

var express = require('express');
var sqlite3 = require('sqlite3').verbose();
var bodyParser = require('body-parser');
var session = require('express-session');
var JsonRequest = require("jsonrequest");
var crypto = require('crypto');
var cookieParser = require('cookie-parser');



/* Objetos globales */
var salt = "RR13'-GjQ:Iy*qU+¿sdJ$qx_{!P/}";
var port = process.env.OPENSHIFT_NODEJS_PORT || 8080;
var ipAddress = process.env.OPENSHIFT_NODEJS_IP;
var app = express();
var db = new sqlite3.Database('database.sqlite');
var latitud;
var longitud;

////////////////////////////////////////////////////
/* Configuración de la sessión */
app.use(cookieParser());
app.use(session({
    secret: 'MY0-GFQ:Iy*qU?8J[727#z5g{Mx',
    resave: false,
    saveUninitialized: true,
    cookie: {
        path: '/',
        maxAge: 1000 * 60 * 2 // 2 horas
    }
}));

app.use(function(req, res, next) {
    res.header('Access-Control-Allow-Credentials', true);
    res.header("Access-Control-Allow-Origin", req.headers.origin);
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE');
    res.header('Access-Control-Allow-Headers', 'X-Requested-With, X-HTTP-Method-Override, Content-Type, Accept');
    next();
});

//////////////////////////////////////////////////////////////////

/* Configuración del analizador del cuerpo (request) y parámetros (response) */

app.use(bodyParser.json()); // Body parser use JSON data
app.use(bodyParser.urlencoded({
    extended: false
}));

app.set('trust proxy', 'loopback');
//////////////////////////////////////////////////////////////////

/* Código a ejecutar al iniciar la conexión a la base de datos */

db.serialize(function() {
    db.run("CREATE TABLE IF NOT EXISTS  usuario ( id  INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, login  TEXT NOT NULL, password  TEXT NOT NULL );");
    db.run("CREATE TABLE IF NOT EXISTS  pregunta (id  INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, titulo TEXT, contenido  TEXT NOT NULL, latitud  REAL,longitud  REAL, ciudad TEXT, usuario_id  INTEGER NOT NULL, CONSTRAINT fk_pregunta_usuario FOREIGN KEY (usuario_id) REFERENCES usuario (id) ON DELETE RESTRICT ON UPDATE CASCADE);");
    db.run("CREATE TABLE IF NOT EXISTS  respuesta (id  INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, contenido  TEXT NOT NULL, usuario_id  INTEGER NOT NULL, pregunta_id  INTEGER NOT NULL, CONSTRAINT fk_respuesta_pregunta FOREIGN KEY (pregunta_id) REFERENCES pregunta (id) ON DELETE CASCADE ON UPDATE CASCADE, CONSTRAINT fk_respuesta_usuario FOREIGN KEY (usuario_id) REFERENCES usuario (id) ON DELETE RESTRICT ON UPDATE CASCADE );");
});

//////////////////////////////////////////////////////////////////
// Definición de las rutas//
//////////////////////////////////////////////////////////////////

app.get('/', function(req, res) {
    res.send('Bienvenido!');

});

/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
////////////////// Rutas para preguntas /////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/* Crear una pregunta */

app.post('/api/preguntas', requireLogin, function(req, res, next) {

    // Establecer el tipo MIME de la respuesta
    res.setHeader("Content-Type", "application/json");

    // Obtener IP
    var ip = req.headers['x-forwarded-for'] ||
        req.connection.remoteAddress ||
        req.socket.remoteAddress ||
        req.connection.socket.remoteAddress;

    // URL del servicio para obtener la locaclización de una máquina según IP
    var url = "http://ipinfo.io/" + ip + "/json";



    // Se realiza la petición del servicio de localización.
    JsonRequest({
        url: url,
    }, function(err, geolocation) {
        if (!err) {
            var ubicacion = geolocation.loc.trim().split(/[ ,]+/);
            latitud  = ubicacion[0];
            longitud = ubicacion[1];
            var ciudad = geolocation.city;
        }
        // Agregar el registro de la nueva entidad a la base de datos
        db.run("INSERT INTO pregunta (titulo, contenido, latitud, longitud, ciudad, usuario_id) VALUES (?, ?, ?, ?, ?, ?)", [req.body.titulo, req.body.contenido, latitud, longitud, ciudad, req.session.user.id], function(err, row) {

            // Verificar si sucedió un error durante la consulta

            if (err) {
                console.error(err);

                res.status(500); // Server Error

                res.json({
                    "error": err
                });
            } else {
                // En caso de éxito

                // Complementar los datos con el 'id' generado autonumérico

                req.body.id = this.lastID;

                res.status(201); // Created

                res.json({
                    "pregunta": req.body,
                    "changes":  this.changes
                });
            }

            res.end();
        });
    });
});

/* Listar TODOS los preguntas */

app.get('/api/preguntas', function(req, res, next) {

    // Establecer el tipo MIME de la respuesta

    res.setHeader("Content-Type", "application/json");

    // Consultar las entidades a la base de datos

    db.all("SELECT * FROM pregunta", function(err, rows) {

        // Verificar si sucedió un error durante la consulta

        if (err) {
            console.error(err);

            res.status(500); // Server Error

            res.json({
                "error": err
            });
        } else {
            // En caso de éxito

            res.status(200); // OK

            // Retornar los registros de la entidad
            res.json({
                "preguntas": rows,
                "usuario": req.session.user
            });
        }
    });
});

/* Actualizar una pregunta */

app.put('/api/preguntas/:id', requireLogin, function(req, res, next) {

    // Establecer el tipo MIME de la respuesta

    res.setHeader("Content-Type", "application/json");

    // Se consulta si la entidad existe
    db.get("SELECT * FROM pregunta WHERE id = ?", [req.params.id], function(err, row) {

        // Verificar si sucedió un error durante la consulta

        if (err) {
            console.error(err);

            res.status(500); // Server Error

            res.json({
                "error": "Ha ocurrido un error por favor inténtalo más tarde"
            });
        } else {
            // Verificar si hubo realmente una respuesta válida

            if (row === undefined) {
                // No se encontró la entidad solicitada

                res.status(404); // Registro no encontrado

                res.json({
                    "error": "El elemento que estaba buscando no fue encontrado"
                });
            } else {
                // En caso de encontrar la entidad
                if (row.usuario_id === req.session.user.id) {

                    // Actualizar el registro

                    db.run("UPDATE pregunta SET titulo = ?, contenido = ? WHERE id = ?", [req.body.titulo, req.body.contenido, req.params.id], function(error, fila) {

                        // Verificar si sucedió un error durante la consulta
                        if (error) {
                            console.error(error);

                            res.status(500); // Server Error

                            res.json({
                                "error": "Ha ocurrido un error por favor inténtalo más tarde"
                            });
                        } else {
                            // En caso de éxito
                            // Complementar los datos con el 'id' suministrado por parámetro

                            req.body.id = req.params.id;

                            res.status(200); // OK

                            res.json({
                                "pregunta": req.body,
                                "changes": this.changes
                            });
                        }
                    });
                } else {
                    res.status(403); // No tiene permisos

                    res.json({
                        "error": "Acceso prohibido"
                    });
                }
            }
        }
    });
    //res.end();
});


//////////////////////////////////////////////////////////////////

/* Obtener información de una pregunta específica */

app.get('/api/preguntas/:id', function(req, res, next) {

    // Establecer el tipo MIME de la respuesta

    res.setHeader("Content-Type", "application/json");

    // Consultar la información de la entidad específica  a la base de datos

    db.get("SELECT * FROM pregunta WHERE id = ?", [req.params.id], function(err, row) {

        // Verificar si sucedió un error durante la consulta

        if (err) {
            console.error(err);

            res.status(500); // Server Error

            res.json({
                "error": err
            });
        } else {
            // Verificar si hubo realmente una respuesta válida

            if (row === undefined) {
                // No se encontró la entidad solicitada

                res.status(404); // Registro no encontrado

                res.json({
                    "error": "El elemento que estaba buscando no fue encontrado"
                });
            } else {
                // En caso de éxito

                res.status(200); // OK

                // Retornar los datos de la entidad

                res.json({
                    "pregunta": row,
                    "usuario": req.session.user
                });
            }
        }

        res.end();
    });
});

//////////////////////////////////////////////////////////////////

/* Eliminar a un pregunta */

app.delete('/api/preguntas/:id', requireLogin, function(req, res, next) {

    // Establecer el tipo MIME de la respuesta

    res.setHeader("Content-Type", "application/json");

    // Se verifica que la entidad exista

    db.get("SELECT * FROM pregunta WHERE id = ?", [req.params.id], function(err, row) {

        // Verificar si sucedió un error durante la consulta

        if (err) {
            console.error(err);

            res.status(500); // Server Error

            res.json({
                "error": err
            });
        } else {
            // Verificar si hubo realmente una respuesta válida

            if (row === undefined) {
                // No se encontró la entidad solicitada

                res.status(404); // Registro no encontrado

                res.json({
                    "error": "El elemento que estaba buscando no fue encontrado"
                });
            } else {
                // En caso de encontrar la entidad se verifica que el usuario
                // es el propietario
                if (row.usuario_id === req.session.user.id) {

                    // Remover el registro de la entidad existente en la base de datos

                    db.run("DELETE FROM pregunta WHERE id = ?", [req.params.id], function(err, row) {

                        // Verificar si sucedió un error durante la consulta

                        if (err) {
                            console.error(err);

                            res.status(500); // Server Error

                            res.json({
                                "error": "Ha ocurrido un error por favor inténtalo más tarde"
                            });
                        } else {
                            // En caso de éxito

                            req.body.id = req.params.id;

                            res.status(200); // OK

                            res.json({
                                "preguntas": req.body,
                                "changes": this.changes
                            });
                        }

                        //res.end();
                    });
                } else {
                    res.status(403); // No tiene permisos

                    res.json({
                        "error": "Acceso prohibido"
                    });
                }
            }
        }
    });
    //res.end();
});
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
////////////////// Rutas para usuario ///////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/* Crear un usuario */

app.post('/api/usuarios', function(req, res, next) {

    // Establecer el tipo MIME de la respuesta

    res.setHeader("Content-Type", "application/json");

    // Agregar el registro de la nueva entidad a la base de datos
    //	var watchID = navigator.geolocation.watchPosition(function(position) {
    //	console.log(position.coords.latitude, position.coords.longitude);
    //	});
    var hash = crypto.createHmac('sha256', salt)
        .update(req.body.password)
        .digest('hex');
    db.run("INSERT INTO usuario (login, password) VALUES (?, ?)", [req.body.login, hash], function(err, row) {

        // Verificar si sucedió un error durante la consulta

        if (err) {
            console.error(err);

            res.status(500); // Server Error

            res.json({
                "error": "Ha ocurrido un error por favor inténtalo más tarde"
            });
        } else {
            // En caso de éxito

            // Complementar los datos con el 'id' generado autonumérico

            req.body.id = this.lastID;

            res.status(201); // Created

            res.json({
                "usuario": req.body.login,
                "changes": this.changes
            });
        }

        res.end();
    });
});


/* Listar todas los preguntas de un usuario*/

app.get('/api/usuarios/:id/preguntas', function(req, res, next) {

    // Establecer el tipo MIME de la respuesta

    res.setHeader("Content-Type", "application/json");

    // Consultar las entidades a la base de datos

    db.all("SELECT * FROM pregunta WHERE usuario_id = ?", [req.params.id], function(err, rows) {

        // Verificar si sucedió un error durante la consulta

        if (err) {
            console.error(err);

            res.status(500); // Server Error

            res.json({
                "error": err
            });
        } else {
            // En caso de éxito

            res.status(200); // OK

            // Retornar los registros de la entidad
            res.json({
                "preguntas": rows,
                "usuario": req.session.user
            });
        }
    });
});
/* Listar TODOS los usuarios */

app.get('/api/usuarios', function(req, res, next) {

    // Establecer el tipo MIME de la respuesta

    res.setHeader("Content-Type", "application/json");

    // Consultar las entidades a la base de datos

    db.all("SELECT * FROM usuario", function(err, rows) {

        // Verificar si sucedió un error durante la consulta

        if (err) {
            console.error(err);

            res.status(500); // Server Error

            res.json({
                "error": "Ha ocurrido un error por favor inténtalo más tarde"
            });
        } else {
            // En caso de éxito

            res.status(200); // OK

            // Retornar los registros de la entidad

            res.json({
                "usuarios": rows,
                "usuario": req.session.user
            });
        }
    });
});

/* Actualizar un usuario */

app.put('/api/usuarios/:id', function(req, res, next) {

    // Establecer el tipo MIME de la respuesta

    res.setHeader("Content-Type", "application/json");

    // Actualizar el registro de la entidad existente en la base de datos
    var hash = crypto.createHmac('sha256', salt)
        .update(req.body.password)
        .digest('hex');
    db.run("UPDATE usuario SET password = ? WHERE id = ?", [hash, req.params.id], function(err, row) {

        // Verificar si sucedió un error durante la consulta

        if (err) {
            console.error(err);

            res.status(500); // Server Error

            res.json({
                "error": err
            });
        } else {
            // Verificar si realmente se realizó 1 actualizaci?n

            if (this.changes === 0) {
                res.status(404); // Registro no encontrado

                res.json({
                    "error": "El elemento que estaba buscando no fue encontrado"
                });
            } else {
                // En caso de éxito

                // Complementar los datos con el 'id' suministrado por par?metro

                req.body.id = req.params.id;

                res.status(200); // OK

                res.json({
                    "usuario": req.body,
                    "changes": this.changes
                });
            }
        }

        res.end();
    });
});


//////////////////////////////////////////////////////////////////

/* Eliminar a un usuario */

app.delete('/api/usuarios/:id', function(req, res, next) {

    // Establecer el tipo MIME de la respuesta

    res.setHeader("Content-Type", "application/json");

    // Remover el registro de la entidad existente en la base de datos

    db.run("DELETE FROM usuario WHERE id = ?", [req.params.id], function(err, row) {

        // Verificar si sucedió un error durante la consulta

        if (err) {
            console.error(err);

            res.status(500); // Server Error

            res.json({
                "error": "Ha ocurrido un error por favor inténtalo más tarde"
            });
        } else {
            // Verificar si realmente se realizó 1 eliminación

            if (this.changes === 0) {
                res.status(404); // Registro no encontrado

                res.json({
                    "error": "El elemento que estaba buscando no fue encontrado"
                });
            } else {
                // En caso de éxito

                req.body.id = req.params.id;

                res.status(200); // OK

                res.json({
                    "usuarios": req.body,
                    "changes": this.changes
                });
            }
        }

        res.end();
    });
});

/* Autenticar un usuario */

app.post('/api/usuarios/autenticar', function(req, res, next) {

    // Establecer el tipo MIME de la respuesta

    res.setHeader("Content-Type", "application/json");

    // Consultar las entidades a la base de datos
    var hash = crypto.createHmac('sha256', salt)
        .update(req.body.password)
        .digest('hex');
    db.get("SELECT usuario.id, usuario.login FROM usuario WHERE usuario.login = ? AND password = ?", [req.body.login, hash], function(err, row) {

        // Verificar si sucedió un error durante la consulta

        if (err) {
            console.error(err);

            res.status(500); // Server Error

            res.json({
                "error": "Ha ocurrido un error por favor inténtalo más tarde"
            });
        } else {
            // Verificar si hubo realmente una respuesta válida

            if (undefined === row) {
                // No se encontro un usuario con el login y password ingresados

                res.status(401); // Usuario no Autorizado

                res.json({
                    "error": "Usuario o contraseña inválidos"
                });
            } else {
                // En caso de éxito se crea la sessión con la el id y login
                // del usuario
                req.session.user = row;
                //res.json({ "usuario" : row });
                res.status(200); // OK
                res.json({
                    "usuario": row
                });
            }
        }
        res.end();
    });
});

/* Ruta para cerrar sessión */

app.get('/api/usuarios/salir', function(req, res) {

    // Se destruye la sessión

    req.session.destroy();

    // Se hace un redirect al listado de preguntas

    res.status(200); // OK
    res.json({
        "status": 200
    });
});


/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
////////////////// Rutas para respuesta /////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/* Crear una respuesta */

app.post('/api/preguntas/:id/respuestas', requireLogin, function(req, res, next) {

    // Establecer el tipo MIME de la respuesta

    res.setHeader("Content-Type", "application/json");

    // Se verifica que exita la pregunta a la cual se desea asociar la respuesta

    db.get("SELECT * FROM pregunta WHERE id = ?", [req.params.id], function(err, row) {

        // Verificar si sucedió un error durante la consulta

        if (err) {
            console.error(err);

            res.status(500); // Server Error

            res.json({
                "error": "Ha ocurrido un error por favor inténtalo más tarde"
            });
        } else {
            // Verificar si hubo realmente una respuesta válida

            if (row === undefined) {
                // No se encontró la entidad solicitada

                res.status(404); // Registro no encontrado

                res.json({
                    "error": "El elemento que estaba buscando no fue encontrado"
                });
            } else {
                // En caso de encontra la respuesta se ingresan los datos de la respuesta

                db.run("INSERT INTO respuesta (contenido, pregunta_id, usuario_id) VALUES (?, ?, ?)", [req.body.contenido, req.params.id, req.session.user.id], function(err, row) {

                    // Verificar si sucedió un error durante la consulta

                    if (err) {
                        console.error(err);

                        res.status(500); // Server Error

                        res.json({
                            "error": "Ha ocurrido un error por favor inténtalo más tarde"
                        });
                    } else {
                        // En caso de éxito

                        // Complementar los datos con el 'id' generado autonumérico

                        req.body.id = this.lastID;

                        res.status(201); // Created

                        res.json({
                            "respuesta": req.body,
                            "changes": this.changes
                        });
                    }

                    //res.end();
                });
            }
        }

        //res.end();
    });

});

/* Listar Todas los respuestas de una pregunta */

app.get('/api/preguntas/:id/respuestas', function(req, res, next) {

    // Establecer el tipo MIME de la respuesta

    res.setHeader("Content-Type", "application/json");

    // Consultar las entidades a la base de datos

    db.all("SELECT respuesta.id, respuesta.contenido, respuesta.usuario_id, respuesta.pregunta_id FROM respuesta INNER JOIN pregunta ON respuesta.pregunta_id = pregunta.id WHERE pregunta.id = ?", [req.params.id], function(err, rows) {

        // Verificar si sucedió un error durante la consulta

        if (err) {
            console.error(err);

            res.status(500); // Server Error

            res.json({
                "error": "Ha ocurrido un error por favor inténtalo más tarde"
            });
        } else {
            // En caso de éxito

            res.status(200); // OK

            // Retornar los registros de la entidad

            res.json({
                "respuestas": rows,
                "usuario": req.session.user
            });
        }
    });
});


/* Eliminar a un respuesta */

app.delete('/api/preguntas/:idPregunta/respuestas/:idRespuesta', requireLogin, function(req, res, next) {
    // Establecer el tipo MIME de la respuesta

    res.setHeader("Content-Type", "application/json");

    // Se verifica que la entidad exista

    db.get("SELECT * FROM respuesta WHERE id = ?", [req.params.idRespuesta], function(err, row) {

        // Verificar si sucedió un error durante la consulta

        if (err) {
            console.error(err);

            res.status(500); // Server Error

            res.json({
                "error": err
            });
        } else {
            // Verificar si hubo realmente una respuesta válida

            if (row === undefined) {
                // No se encontró la entidad solicitada

                res.status(404); // Registro no encontrado

                res.json({
                    "error": "Elemento no encontrado"
                });
            } else {
                // En caso de encontrar la entidad se verifica que el usuario
                // es el propietario
                if (row.usuario_id === req.session.user.id) {

                    // Remover el registro de la entidad existente en la base de datos

                    db.run("DELETE FROM respuesta WHERE id = ?", [req.params.idRespuesta], function(err, row) {

                        // Verificar si sucedió un error durante la consulta

                        if (err) {
                            console.error(err);

                            res.status(500); // Server Error

                            res.json({
                                "error": err
                            });
                        } else {
                            // En caso de éxito

                            req.body.id = req.params.id;

                            res.status(200); // OK

                            res.json({
                                "respuestas": req.body,
                                "changes": this.changes
                            });
                        }

                        res.end();
                    });
                } else {
                    res.status(403); // No tiene permisos

                    res.json({
                        "error": "Acceso prohibido"
                    });
                }
            }
        }
    });
    //res.end();
});


/**
 * Verifica que la sessión de usuario exista
 *
 * @param Request
 * @param Response
 * @param function
 * @returns
 */
function requireLogin(req, res, next) {
    if (!req.session.user) {
        res.status(401);
        res.json({
            "error": "Usuario no Autenticado"
        });
    } else {
        next();
    }
}
/* Iniciar el servicio a través del puerto elegido */

app.listen(port, ipAddress);

console.log('Server listening on ' + ipAddress + ' port ' + port);

//////////////////////////////////////////////////////////////////
