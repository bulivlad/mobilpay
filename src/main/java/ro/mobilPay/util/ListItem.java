package ro.mobilPay.util;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.io.Serializable;

@Data
@AllArgsConstructor
public class ListItem implements Serializable
{
  /**
	 * 
	 */
    private static final long serialVersionUID = -6532335112800057526L;
    public String id;
    public String key;
    public String val;
  
    public ListItem(String id, String key) {
    this.id = id;
    this.key = key;
    this.val = null;
    }

}