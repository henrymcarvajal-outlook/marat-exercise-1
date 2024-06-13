//using System;
//using System.Collections.Generic;
//using System.ComponentModel;
//using System.Net.Http;
//using System.Net.Http.Formatting;
//using System.Net.Http.Headers;
//using System.Net.Http.Properties;
//using System.Threading;
//using System.Threading.Tasks;
//using System.Web.Http;

//namespace WebNet4_8.App_Start.OidcSecurity
//{
//    [EditorBrowsable(EditorBrowsableState.Never)]
//    public static class HttpContentExtensions
//    {
//        private static MediaTypeFormatterCollection _defaultMediaTypeFormatterCollection;

//        private static MediaTypeFormatterCollection DefaultMediaTypeFormatterCollection
//        {
//            get
//            {
//                if (_defaultMediaTypeFormatterCollection == null)
//                {
//                    _defaultMediaTypeFormatterCollection = new MediaTypeFormatterCollection();
//                }

//                return _defaultMediaTypeFormatterCollection;
//            }
//        }

//        //
//        // Summary:
//        //     Returns a Task that will yield an object of the specified type from the content
//        //     instance.
//        //
//        // Parameters:
//        //   content:
//        //     The HttpContent instance from which to read.
//        //
//        //   type:
//        //     The type of the object to read.
//        //
//        // Returns:
//        //     A Task that will yield an object instance of the specified type.
//        public static Task<object> ReadAsAsync(this HttpContent content, Type type)
//        {
//            return content.ReadAsAsync(type, DefaultMediaTypeFormatterCollection);
//        }

//        //
//        // Summary:
//        //     Returns a Task that will yield an object of the specified type from the content
//        //     instance using one of the provided formatters to deserialize the content.
//        //
//        // Parameters:
//        //   content:
//        //     The HttpContent instance from which to read.
//        //
//        //   type:
//        //     The type of the object to read.
//        //
//        //   cancellationToken:
//        //     The token to cancel the operation.
//        //
//        // Returns:
//        //     An object instance of the specified type.
//        public static Task<object> ReadAsAsync(this HttpContent content, Type type, CancellationToken cancellationToken)
//        {
//            return content.ReadAsAsync(type, DefaultMediaTypeFormatterCollection, cancellationToken);
//        }

//        //
//        // Summary:
//        //     Returns a Task that will yield an object of the specified type from the content
//        //     instance using one of the provided formatters to deserialize the content.
//        //
//        // Parameters:
//        //   content:
//        //     The HttpContent instance from which to read.
//        //
//        //   type:
//        //     The type of the object to read.
//        //
//        //   formatters:
//        //     The collection of MediaTypeFormatter instances to use.
//        //
//        // Returns:
//        //     An object instance of the specified type.
//        public static Task<object> ReadAsAsync(this HttpContent content, Type type, IEnumerable<MediaTypeFormatter> formatters)
//        {
//            return ReadAsAsync<object>(content, type, formatters, null);
//        }

//        //
//        // Summary:
//        //     Returns a Task that will yield an object of the specified type from the content
//        //     instance using one of the provided formatters to deserialize the content.
//        //
//        // Parameters:
//        //   content:
//        //     The HttpContent instance from which to read.
//        //
//        //   type:
//        //     The type of the object to read.
//        //
//        //   formatters:
//        //     The collection of MediaTypeFormatter instances to use.
//        //
//        //   cancellationToken:
//        //     The token to cancel the operation.
//        //
//        // Returns:
//        //     An object instance of the specified type.
//        public static Task<object> ReadAsAsync(this HttpContent content, Type type, IEnumerable<MediaTypeFormatter> formatters, CancellationToken cancellationToken)
//        {
//            return ReadAsAsync<object>(content, type, formatters, null, cancellationToken);
//        }

//        //
//        // Summary:
//        //     Returns a Task that will yield an object of the specified type from the content
//        //     instance using one of the provided formatters to deserialize the content.
//        //
//        // Parameters:
//        //   content:
//        //     The HttpContent instance from which to read.
//        //
//        //   type:
//        //     The type of the object to read.
//        //
//        //   formatters:
//        //     The collection of MediaTypeFormatter instances to use.
//        //
//        //   formatterLogger:
//        //     The IFormatterLogger to log events to.
//        //
//        // Returns:
//        //     An object instance of the specified type.
//        public static Task<object> ReadAsAsync(this HttpContent content, Type type, IEnumerable<MediaTypeFormatter> formatters, IFormatterLogger formatterLogger)
//        {
//            return ReadAsAsync<object>(content, type, formatters, formatterLogger);
//        }

//        //
//        // Summary:
//        //     Returns a Task that will yield an object of the specified type from the content
//        //     instance using one of the provided formatters to deserialize the content.
//        //
//        // Parameters:
//        //   content:
//        //     The HttpContent instance from which to read.
//        //
//        //   type:
//        //     The type of the object to read.
//        //
//        //   formatters:
//        //     The collection of MediaTypeFormatter instances to use.
//        //
//        //   formatterLogger:
//        //     The IFormatterLogger to log events to.
//        //
//        //   cancellationToken:
//        //     The token to cancel the operation.
//        //
//        // Returns:
//        //     An object instance of the specified type.
//        public static Task<object> ReadAsAsync(this HttpContent content, Type type, IEnumerable<MediaTypeFormatter> formatters, IFormatterLogger formatterLogger, CancellationToken cancellationToken)
//        {
//            return ReadAsAsync<object>(content, type, formatters, formatterLogger, cancellationToken);
//        }

//        //
//        // Summary:
//        //     Returns a Task that will yield an object of the specified type <typeparamref
//        //     name="T" /> from the content instance.
//        //
//        // Parameters:
//        //   content:
//        //     The HttpContent instance from which to read.
//        //
//        // Type parameters:
//        //   T:
//        //     The type of the object to read.
//        //
//        // Returns:
//        //     An object instance of the specified type.
//        public static Task<T> ReadAsAsync<T>(this HttpContent content)
//        {
//            return content.ReadAsAsync<T>(DefaultMediaTypeFormatterCollection);
//        }

//        //
//        // Summary:
//        //     Returns a Task that will yield an object of the specified type from the content
//        //     instance.
//        //
//        // Parameters:
//        //   content:
//        //     The HttpContent instance from which to read.
//        //
//        //   cancellationToken:
//        //     The token to cancel the operation.
//        //
//        // Type parameters:
//        //   T:
//        //     The type of the object to read.
//        //
//        // Returns:
//        //     An object instance of the specified type.
//        public static Task<T> ReadAsAsync<T>(this HttpContent content, CancellationToken cancellationToken)
//        {
//            return content.ReadAsAsync<T>(DefaultMediaTypeFormatterCollection, cancellationToken);
//        }

//        //
//        // Summary:
//        //     Returns a Task that will yield an object of the specified type <typeparamref
//        //     name="T" /> from the content instance.
//        //
//        // Parameters:
//        //   content:
//        //     The HttpContent instance from which to read.
//        //
//        //   formatters:
//        //     The collection of MediaTyepFormatter instances to use.
//        //
//        // Type parameters:
//        //   T:
//        //     The type of the object to read.
//        //
//        // Returns:
//        //     An object instance of the specified type.
//        public static Task<T> ReadAsAsync<T>(this HttpContent content, IEnumerable<MediaTypeFormatter> formatters)
//        {
//            return ReadAsAsync<T>(content, typeof(T), formatters, null);
//        }

//        //
//        // Summary:
//        //     Returns a Task that will yield an object of the specified type from the content
//        //     instance.
//        //
//        // Parameters:
//        //   content:
//        //     The HttpContent instance from which to read.
//        //
//        //   formatters:
//        //     The collection of MediaTypeFormatter instances to use.
//        //
//        //   cancellationToken:
//        //     The token to cancel the operation.
//        //
//        // Type parameters:
//        //   T:
//        //     The type of the object to read.
//        //
//        // Returns:
//        //     An object instance of the specified type.
//        public static Task<T> ReadAsAsync<T>(this HttpContent content, IEnumerable<MediaTypeFormatter> formatters, CancellationToken cancellationToken)
//        {
//            return ReadAsAsync<T>(content, typeof(T), formatters, null, cancellationToken);
//        }

//        //
//        // Summary:
//        //     Returns a Task that will yield an object of the specified type <typeparamref
//        //     name="T" /> from the content instance.
//        //
//        // Parameters:
//        //   content:
//        //     The HttpContent instance from which to read.
//        //
//        //   formatters:
//        //     The collection of MediaTypeFormatter instances to use.
//        //
//        //   formatterLogger:
//        //     The IFormatterLogger to log events to.
//        //
//        // Type parameters:
//        //   T:
//        //     The type of the object to read.
//        //
//        // Returns:
//        //     An object instance of the specified type.
//        public static Task<T> ReadAsAsync<T>(this HttpContent content, IEnumerable<MediaTypeFormatter> formatters, IFormatterLogger formatterLogger)
//        {
//            return ReadAsAsync<T>(content, typeof(T), formatters, formatterLogger);
//        }

//        //
//        // Summary:
//        //     Returns a Task that will yield an object of the specified type from the content
//        //     instance.
//        //
//        // Parameters:
//        //   content:
//        //     The HttpContent instance from which to read.
//        //
//        //   formatters:
//        //     The collection of MediaTypeFormatter instances to use.
//        //
//        //   formatterLogger:
//        //     The IFormatterLogger to log events to.
//        //
//        //   cancellationToken:
//        //     The token to cancel the operation.
//        //
//        // Type parameters:
//        //   T:
//        //     The type of the object to read.
//        //
//        // Returns:
//        //     An object instance of the specified type.
//        public static Task<T> ReadAsAsync<T>(this HttpContent content, IEnumerable<MediaTypeFormatter> formatters, IFormatterLogger formatterLogger, CancellationToken cancellationToken)
//        {
//            return ReadAsAsync<T>(content, typeof(T), formatters, formatterLogger, cancellationToken);
//        }

//        private static Task<T> ReadAsAsync<T>(HttpContent content, Type type, IEnumerable<MediaTypeFormatter> formatters, IFormatterLogger formatterLogger)
//        {
//            return ReadAsAsync<T>(content, type, formatters, formatterLogger, CancellationToken.None);
//        }

//        private static Task<T> ReadAsAsync<T>(HttpContent content, Type type, IEnumerable<MediaTypeFormatter> formatters, IFormatterLogger formatterLogger, CancellationToken cancellationToken)
//        {
//            if (content == null)
//            {
//                throw  new ArgumentNullException("content");
//            }

//            if (type == null)
//            {
//                throw new ArgumentNullException("type");
//            }

//            if (formatters == null)
//            {
//                throw new ArgumentNullException("formatters");
//            }

//            if (content is ObjectContent objectContent && objectContent.Value != null && type.IsAssignableFrom(objectContent.Value.GetType()))
//            {
//                return Task.FromResult((T)objectContent.Value);
//            }

//            MediaTypeFormatter mediaTypeFormatter = null;
//            var defaultApplicationOctetStreamMediaType = new MediaTypeHeaderValue("application/octet-stream");
            
//            MediaTypeHeaderValue mediaTypeHeaderValue = content.Headers.ContentType ?? defaultApplicationOctetStreamMediaType;
//            mediaTypeFormatter = new MediaTypeFormatterCollection(formatters).FindReader(type, mediaTypeHeaderValue);
//            if (mediaTypeFormatter == null)
//            {
//                if (content.Headers.ContentLength == 0)
//                {
//                    T result = (T)MediaTypeFormatter.GetDefaultValueForType(type);
//                    return Task.FromResult(result);
//                }
//                throw new UnsupportedMediaTypeException($"No Read Serializer Available for: {type.Name}, value: {mediaTypeHeaderValue}", mediaTypeHeaderValue);
//            }

//            return ReadAsAsyncCore<T>(content, type, formatterLogger, mediaTypeFormatter, cancellationToken);
//        }

//        private static async Task<T> ReadAsAsyncCore<T>(HttpContent content, Type type, IFormatterLogger formatterLogger, MediaTypeFormatter formatter, CancellationToken cancellationToken)
//        {
//            cancellationToken.ThrowIfCancellationRequested();
//            return (T)(await formatter.ReadFromStreamAsync(type, await content.ReadAsStreamAsync(), content, formatterLogger, cancellationToken));
//        }
//    }
//}