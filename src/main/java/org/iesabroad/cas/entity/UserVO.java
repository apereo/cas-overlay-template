package org.iesabroad.cas.entity;

import lombok.Getter;
import lombok.Setter;
import org.iesabroad.cas.util.BooleanToStringConverter;

import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.Table;
import java.io.Serializable;
import java.util.Date;

/**
 * Copy of the original UserVO from Cerberus-Server, modified to use hibernate annotations and replace business logic dependent fields
 *
 * @author D. Ashmore
 * @author M. Koehler
 *
 */
@Entity
@Table(name="CER_ACCOUNT", schema = "cerbadm" )
public class UserVO implements Serializable {
	private static final long serialVersionUID = 8483665655411904820L;

	@Column (name = "Uid")
	@Getter
	@Setter
	@javax.persistence.Id
	private String userId;

	@Column(name = "Email")
	@Getter
	@Setter
	private String email;

	@Column (name = "Ies_School_Email")
	@Getter
	@Setter
	private String schoolEmail;

	@Column (name="Employee_Type")
	@Getter
	@Setter
	private String employeeType;

	@Column (name="Ies_User_Enabled")
	@Convert(converter=BooleanToStringConverter.class)
	@Getter
	@Setter
	private Boolean userEnabled;

	@Column (name="Ies_Password_Reset_Req")
	@Convert(converter= BooleanToStringConverter.class)
	@Getter
	@Setter
	private Boolean passwordResetRequested;

	@Column(name="Ies_Password_Change_Date")
	@Getter
	@Setter
	private Date passwordChangeDate;

//	@Getter
//	@Setter
//	private Set<String> userApplicationSet = new HashSet<>();
//
//	@Getter
//	@Setter
//	private Set<String> userRoleSet = new HashSet<>();


}
