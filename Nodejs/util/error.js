exports.errorHandler = (next, err) => {
  const error = new Error(err);

  error.httpStatusCode = 500;

  return next(err);
};
