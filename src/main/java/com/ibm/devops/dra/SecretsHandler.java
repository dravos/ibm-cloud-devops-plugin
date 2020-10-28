/*
* Custom handler to filter log messages.
*/

import java.util.logging.LogRecord;
import java.util.logging.StreamHandler;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SecretsHandler extends StreamHandler {

   private static String KEY_REGEX = "([a-zA-Z0-9]+[_-])*(email|key|apikey|pass|passphrase|password|phone|secret|token|credentials|authorization|role_id|workerQueueCredentials|value)([_-][a-zA-Z0-9]+)*";
   private static String EMAIL_REGEX = "\\b[-A-Z0-9._%+]+(?:@|%40)[-A-Z0-9.%]+(?:\\.|%2E)[A-Z]{2,}\\b";
   private static String EMAIL_TEST_REGEX = "(?:@|%40)";
   private static Pattern emailPattern = Pattern.compile(EMAIL_REGEX, Pattern.CASE_INSENSITIVE);
   private static Pattern emailTest = Pattern.compile(EMAIL_TEST_REGEX, Pattern.CASE_INSENSITIVE);

   public static String filter(String logData) {
      // filter usernames and passwords out of URLs
      String data = logData;
      data = logData.replaceAll("://\\S+:\\S+@", "://");

      Matcher testMatcher = emailTest.matcher(data);
      if (testMatcher.find()) {
          Matcher emailMatcher = emailPattern.matcher(data);
          data = emailMatcher.replaceAll("***");
      }
      String stringFilter = String.format("\"(%s\\\\*\": ?\\\\*)\"[^\"\\\\]+(\\\\*)\"", KEY_REGEX);
      Pattern stringFilterPattern = Pattern.compile(stringFilter, Pattern.CASE_INSENSITIVE & Pattern.MULTILINE);
      return stringFilterPattern.matcher(data).replaceAll("\"$1\"***\"");
   }

    @Override
    public void publish(LogRecord record) {
        String message = record.getMessage();
        String filteredMessage = filter(message);
        record.setMessage(filteredMessage);
        super.publish(record);
    }

    @Override
    public void flush() {
        super.flush();
    }

    @Override
    public void close() throws SecurityException {
        super.close();
    }
}