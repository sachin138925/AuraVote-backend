import winston from 'winston';

export const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

// morgan stream
export const stream = {
  write: (message) => logger.http ? logger.http(message.trim()) : logger.info(message.trim())
};
