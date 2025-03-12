const { createLogger, format, transports} = require('winston');

//Create a Winston Logger
const logger = createLogger({
    level: 'info',
    format: format.combine(
        format.timestamp(),
        format.errors({stack: true}),
        format.json()
    ),
    transports: [
        new transports.Console({ format: format.simple()}),
        new transports.File({ filename: 'error.log', level: 'error'}), //log errors to a file
        new transports.File({ filename: 'combined.log'}), //Log all levels
    ],
});
